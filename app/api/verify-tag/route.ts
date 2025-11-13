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

    // 먼저 PICC 데이터에서 UID와 카운터만 파싱 (리플레이 검사 전)
    const { parseNTAG424Data } = await import('@/lib/ntag424');
    const parsedData = parseNTAG424Data(tagData.piccData);

    console.log('[VERIFY] Parsed data:', parsedData);

    if (!parsedData) {
      return NextResponse.json({
        success: false,
        message: 'Invalid tag data format',
        reason: 'Could not parse PICC data',
      }, { status: 400 });
    }

    // 태그 소유자 확인 (리플레이 검사 전에 먼저 확인)
    const owner = await getTagOwner(parsedData.uid);
    console.log('[VERIFY] Owner lookup for UID', parsedData.uid, ':', owner);
    console.log('[VERIFY] Current user:', session.user.email);

    // 미등록 태그는 리플레이 검사 없이 등록 제안
    if (!owner) {
      // 기본 CMAC 검증만 수행
      const result = await verifyNTAG424(tagData, aesKey, true); // skipReplayCheck = true

      if (!result.valid && result.reason !== 'Replay attack detected - counter already used or invalid') {
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

      return NextResponse.json({
        success: false,
        needsRegistration: true,
        message: 'Tag not registered',
        reason: 'This tag is not connected to any account. Would you like to connect it?',
        data: {
          uid: parsedData.uid,
          counter: parsedData.counter,
        },
      });
    }

    // 등록된 태그는 전체 검증 (리플레이 공격 포함)
    const result = await verifyNTAG424(tagData, aesKey, false);

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
