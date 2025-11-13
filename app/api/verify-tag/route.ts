import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth.config';
import { verifyNTAG424, parseNTAG424URL } from '@/lib/ntag424';
import { getTagOwner } from '@/lib/kv';

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user?.email) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized', reason: 'Please login first' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { url, piccData, cmac } = body;

    const aesKey = process.env.NTAG424_AES_KEY;
    if (!aesKey) {
      return NextResponse.json(
        { success: false, message: 'Server configuration error', reason: 'AES key not set' },
        { status: 500 }
      );
    }

    let tagData;

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
    
    // 태그가 등록되지 않은 경우 - 등록 제안
    if (!owner) {
      return NextResponse.json({
        success: false,
        needsRegistration: true,
        message: 'Tag not registered',
        reason: 'This tag is not connected to any account. Would you like to connect it?',
        data: {
          uid: result.uid,
          counter: result.counter,
        },
      });
    }

    // 태그가 다른 사용자에게 등록된 경우
    if (owner !== session.user.email) {
      return NextResponse.json({
        success: false,
        message: 'Access denied',
        reason: 'This tag is already registered to another user',
        data: {
          uid: result.uid,
          counter: result.counter,
        },
      }, { status: 403 });
    }

    // 모든 검증 통과 - 자신의 태그
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
