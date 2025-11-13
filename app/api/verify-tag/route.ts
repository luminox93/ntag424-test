import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth.config';
import { verifyNTAG424, parseNTAG424URL } from '@/lib/ntag424';
import { getTagOwner } from '@/lib/kv';

export async function POST(request: NextRequest) {
  try {
    // 인증 확인
    const session = await getServerSession(authOptions);
    if (!session?.user?.email) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized', reason: 'Please login first' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { url, piccData, cmac } = body;

    // AES 키 가져오기
    const aesKey = process.env.NTAG424_AES_KEY;
    if (!aesKey) {
      return NextResponse.json(
        { success: false, message: 'Server configuration error', reason: 'AES key not set' },
        { status: 500 }
      );
    }

    let tagData;

    // URL에서 파싱하거나 직접 제공된 데이터 사용
    if (url) {
      tagData = parseNTAG424URL(url);
      if (!tagData) {
        return NextResponse.json(
          { success: false, message: 'Invalid NTAG424 URL format' },
          { status: 400 }
        );
      }
    } else if (piccData && cmac) {
      tagData = { piccData, cmac };
    } else {
      return NextResponse.json(
        { success: false, message: 'Missing required parameters', reason: 'url or (piccData and cmac) required' },
        { status: 400 }
      );
    }

    // 태그 검증 (CMAC, 리플레이 공격)
    const result = await verifyNTAG424(tagData, aesKey);

    if (!result.valid) {
      return NextResponse.json({
        success: false,
        message: 'Tag verification failed',
        reason: result.reason,
        data: {
          uid: result.uid,
          counter: result.counter,
        },
      }, { status: 400 });
    }

    // 태그 소유자 확인
    const owner = await getTagOwner(result.uid!);
    if (!owner) {
      return NextResponse.json({
        success: false,
        message: 'Access denied',
        reason: 'Tag not registered to any user',
        data: {
          uid: result.uid,
          counter: result.counter,
        },
      }, { status: 403 });
    }

    if (owner !== session.user.email) {
      return NextResponse.json({
        success: false,
        message: 'Access denied',
        reason: 'Tag is registered to another user',
        data: {
          uid: result.uid,
          counter: result.counter,
        },
      }, { status: 403 });
    }

    // 모든 검증 통과
    return NextResponse.json({
      success: true,
      message: 'Access granted',
      data: {
        uid: result.uid,
        counter: result.counter,
        user: session.user.email,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error('Tag verification error:', error);
    return NextResponse.json(
      {
        success: false,
        message: 'Internal server error',
        reason: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
