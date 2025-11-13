import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth.config';
import { verifyNTAG424, parseNTAG424URL } from '@/lib/ntag424';

export async function POST(request: NextRequest) {
  try {
    // 인증 확인
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { url, piccData, cmac } = body;

    // AES 키 가져오기
    const aesKey = process.env.NTAG424_AES_KEY;
    if (!aesKey) {
      return NextResponse.json(
        { error: 'Server configuration error - AES key not set' },
        { status: 500 }
      );
    }

    let tagData;

    // URL에서 파싱하거나 직접 제공된 데이터 사용
    if (url) {
      tagData = parseNTAG424URL(url);
      if (!tagData) {
        return NextResponse.json(
          { error: 'Invalid NTAG424 URL format' },
          { status: 400 }
        );
      }
    } else if (piccData && cmac) {
      tagData = { piccData, cmac };
    } else {
      return NextResponse.json(
        { error: 'Missing required parameters: url or (piccData and cmac)' },
        { status: 400 }
      );
    }

    // 태그 검증
    const result = await verifyNTAG424(tagData, aesKey);

    if (result.valid) {
      return NextResponse.json({
        success: true,
        message: 'Tag verified successfully',
        data: {
          uid: result.uid,
          counter: result.counter,
          user: session.user?.email,
          timestamp: new Date().toISOString(),
        },
      });
    } else {
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
  } catch (error) {
    console.error('Tag verification error:', error);
    return NextResponse.json(
      {
        error: 'Internal server error',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// GET 메서드로 URL 파라미터를 통한 검증도 지원
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    const url = request.url;
    const aesKey = process.env.NTAG424_AES_KEY;

    if (!aesKey) {
      return NextResponse.json(
        { error: 'Server configuration error - AES key not set' },
        { status: 500 }
      );
    }

    const tagData = parseNTAG424URL(url);
    if (!tagData) {
      return NextResponse.json(
        { error: 'Invalid NTAG424 URL format' },
        { status: 400 }
      );
    }

    const result = await verifyNTAG424(tagData, aesKey);

    if (result.valid) {
      return NextResponse.json({
        success: true,
        message: 'Tag verified successfully',
        data: {
          uid: result.uid,
          counter: result.counter,
          user: session.user?.email,
          timestamp: new Date().toISOString(),
        },
      });
    } else {
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
  } catch (error) {
    console.error('Tag verification error:', error);
    return NextResponse.json(
      {
        error: 'Internal server error',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
