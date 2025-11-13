import { kv } from '@vercel/kv';

/**
 * 태그 UID와 사용자 이메일 매핑 관리
 */

// 태그를 사용자에게 등록
export async function registerTag(uid: string, userEmail: string): Promise<void> {
  const key = `tag:${uid}`;
  console.log('[KV] Setting key:', key, 'value:', userEmail);
  await kv.set(key, userEmail);
  console.log('[KV] Set complete');
}

// 태그의 소유자 조회
export async function getTagOwner(uid: string): Promise<string | null> {
  const key = `tag:${uid}`;
  console.log('[KV] Getting key:', key);
  const result = await kv.get<string>(key);
  console.log('[KV] Get result:', result);
  return result;
}

// 사용자의 모든 태그 조회
export async function getUserTags(userEmail: string): Promise<string[]> {
  const keys = await kv.keys('tag:*');
  const tags: string[] = [];
  
  for (const key of keys) {
    const owner = await kv.get<string>(key);
    if (owner === userEmail) {
      tags.push(key.replace('tag:', ''));
    }
  }
  
  return tags;
}

// 태그 등록 해제
export async function unregisterTag(uid: string): Promise<void> {
  await kv.del(`tag:${uid}`);
}

// 카운터 저장 (리플레이 공격 방지)
export async function saveCounter(uid: string, counter: number): Promise<void> {
  await kv.zadd(`counters:${uid}`, { score: counter, member: counter.toString() });
  
  // 최근 1000개만 유지
  const count = await kv.zcard(`counters:${uid}`);
  if (count > 1000) {
    await kv.zpopmin(`counters:${uid}`, count - 1000);
  }
}

// 카운터가 사용되었는지 확인
export async function isCounterUsed(uid: string, counter: number): Promise<boolean> {
  const score = await kv.zscore(`counters:${uid}`, counter.toString());
  return score !== null;
}

// 최대 카운터 값 조회
export async function getMaxCounter(uid: string): Promise<number> {
  const max = await kv.zrange(`counters:${uid}`, -1, -1, { withScores: true }) as Array<{member: string, score: number}>;
  if (max.length === 0) return 0;
  return max[0].score;
}
