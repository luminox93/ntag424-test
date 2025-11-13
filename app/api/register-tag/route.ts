import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth.config';
import { registerTag, getTagOwner, getUserTags } from '@/lib/kv';

// 태그 등록
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { uid } = body;

    if (!uid) {
      return NextResponse.json(
        { error: 'Missing required parameter: uid' },
        { status: 400 }
      );
    }

    // 이미 등록된 태그인지 확인
    const existingOwner = await getTagOwner(uid);
    if (existingOwner) {
      if (existingOwner === session.user.email) {
        return NextResponse.json(
          { success: false, message: 'Tag already registered to you' },
          { status: 400 }
        );
      } else {
        return NextResponse.json(
          { success: false, message: 'Tag already registered to another user' },
          { status: 403 }
        );
      }
    }

    // 태그 등록
    await registerTag(uid, session.user.email);

    return NextResponse.json({
      success: true,
      message: 'Tag registered successfully',
      data: {
        uid,
        owner: session.user.email,
      },
    });
  } catch (error) {
    console.error('Tag registration error:', error);
    return NextResponse.json(
      {
        error: 'Internal server error',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// 사용자의 등록된 태그 목록 조회
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user?.email) {
      return NextResponse.json(
        { error: 'Unauthorized - Please login first' },
        { status: 401 }
      );
    }

    const tags = await getUserTags(session.user.email);

    return NextResponse.json({
      success: true,
      data: {
        tags,
        count: tags.length,
      },
    });
  } catch (error) {
    console.error('Get tags error:', error);
    return NextResponse.json(
      {
        error: 'Internal server error',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
