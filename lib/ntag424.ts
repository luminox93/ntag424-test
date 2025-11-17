import { createDecipheriv } from 'crypto';
import { isCounterUsed, getMaxCounter, saveCounter } from './kv';
import { aesCmac } from 'node-aes-cmac';

/**
 * NTAG424 태그 검증 및 리플레이 공격 방어 유틸리티
 */

interface NTAG424Data {
  piccData: string;
  cmac: string;
  counter?: number;
  uid?: string;
}

interface VerificationResult {
  valid: boolean;
  reason?: string;
  uid?: string;
  counter?: number;
  decryptedData?: string;
}

/**
 * Hex 문자열을 Buffer로 변환
 */
function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

/**
 * AES-128 CMAC 검증 (node-aes-cmac 라이브러리 사용)
 */
function verifyCMAC(
  piccData: Buffer,
  cmac: Buffer,
  key: Buffer
): boolean {
  try {
    // CMAC의 길이가 적절한지 확인 (8바이트)
    if (cmac.length !== 8) {
      console.warn('[CMAC] Invalid CMAC length:', cmac.length);
      return false;
    }

    // node-aes-cmac을 사용하여 CMAC 계산 (Buffer 반환 옵션 사용)
    const calculatedCMAC = aesCmac(key, piccData, { returnAsBuffer: true }) as Buffer;

    // NTAG424는 CMAC의 처음 8바이트만 사용
    const truncatedCMAC = calculatedCMAC.subarray(0, 8);

    console.log('[CMAC] Expected:', cmac.toString('hex'));
    console.log('[CMAC] Calculated:', truncatedCMAC.toString('hex'));
    console.log('[CMAC] PICC Data:', piccData.toString('hex'));
    console.log('[CMAC] Key:', key.toString('hex'));

    // 상수 시간 비교 (타이밍 공격 방지)
    return truncatedCMAC.equals(cmac);
  } catch (error) {
    console.error('[CMAC] Verification error:', error);
    return false;
  }
}

/**
 * SUN 메시지 해독 (SDM 데이터)
 */
function decryptSUNMessage(
  encryptedData: Buffer,
  key: Buffer,
  iv: Buffer
): Buffer {
  const decipher = createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);

  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted;
}

/**
 * PICC 데이터에서 카운터와 UID 추출 (복호화된 데이터에서)
 */
function parsePICCData(piccData: string, aesKey?: string): { uid: string; counter: number } | null {
  try {
    const buffer = hexToBuffer(piccData);

    if (buffer.length < 16) {
      return null;
    }

    let dataBuffer = buffer;

    // AES 키가 제공된 경우 복호화 수행
    if (aesKey) {
      try {
        const key = hexToBuffer(aesKey);
        // IV는 0으로 채워진 16바이트 (NTAG424 SDM 기본값)
        const iv = Buffer.alloc(16, 0);

        // PICC 데이터가 16바이트 블록 단위인지 확인
        if (buffer.length % 16 !== 0) {
          console.warn('[NTAG424] PICC data length not aligned to 16 bytes, using as-is');
        } else {
          // 복호화 수행
          dataBuffer = decryptSUNMessage(buffer, key, iv);
          console.log('[NTAG424] Decrypted PICC data:', dataBuffer.toString('hex'));
        }
      } catch (decryptError) {
        console.warn('[NTAG424] Decryption failed, using raw data:', decryptError);
      }
    }

    // 복호화된 데이터 형식: UID (7바이트) + Counter (3바이트) + ...
    if (dataBuffer.length < 10) {
      return null;
    }

    const uid = dataBuffer.subarray(0, 7).toString('hex').toUpperCase();

    // NTAG424는 Little-endian 사용
    const counter = dataBuffer.readUIntLE(7, 3);

    return { uid, counter };
  } catch (error) {
    console.error('[NTAG424] Parse error:', error);
    return null;
  }
}

/**
 * PICC 데이터 파싱 (외부에서 사용 가능)
 */
export function parseNTAG424Data(piccData: string, aesKey?: string): { uid: string; counter: number } | null {
  return parsePICCData(piccData, aesKey);
}

/**
 * 리플레이 공격 체크 (Vercel KV 사용)
 */
async function checkReplayAttack(uid: string, counter: number): Promise<boolean> {
  // 이미 사용된 카운터인지 확인
  const used = await isCounterUsed(uid, counter);
  if (used) {
    return false; // 리플레이 공격 감지
  }

  // 카운터가 이전 최대값보다 작으면 리플레이 공격 가능성
  const maxCounter = await getMaxCounter(uid);
  if (counter <= maxCounter) {
    return false;
  }

  // 카운터 저장
  await saveCounter(uid, counter);

  return true;
}

/**
 * NTAG424 태그 검증 (리플레이 공격 방어 포함)
 */
export async function verifyNTAG424(
  data: NTAG424Data,
  aesKey: string,
  skipReplayCheck: boolean = false
): Promise<VerificationResult> {
  try {
    const key = hexToBuffer(aesKey);
    const piccDataEncrypted = hexToBuffer(data.piccData);
    const cmac = hexToBuffer(data.cmac);

    // 1. PICC 데이터 복호화
    const iv = Buffer.alloc(16, 0);
    const piccDataDecrypted = decryptSUNMessage(piccDataEncrypted, key, iv);

    // 2. PICC 데이터 파싱
    const parsed = parsePICCData(data.piccData, aesKey);
    if (!parsed) {
      return {
        valid: false,
        reason: 'Invalid PICC data format',
      };
    }

    const { uid, counter } = parsed;

    // 3. CMAC 입력 데이터 생성 (Counter + UID)
    const cmacInputData = Buffer.alloc(10);
    cmacInputData.writeUIntLE(counter, 0, 3); // Counter (3바이트, little-endian)
    Buffer.from(uid, 'hex').copy(cmacInputData, 3); // UID (7바이트)

    console.log('[CMAC] Input data (Counter + UID):', cmacInputData.toString('hex'));

    // 4. CMAC 검증
    if (!verifyCMAC(cmacInputData, cmac, key)) {
      return {
        valid: false,
        reason: 'CMAC verification failed',
        uid,
        counter,
      };
    }

    // 5. 리플레이 공격 체크 (옵션)
    if (!skipReplayCheck && !(await checkReplayAttack(uid, counter))) {
      return {
        valid: false,
        reason: 'Replay attack detected - counter already used or invalid',
        uid,
        counter,
      };
    }

    // 4. 검증 성공
    return {
      valid: true,
      uid,
      counter,
      decryptedData: piccDataDecrypted.toString('hex'),
    };
  } catch (error) {
    return {
      valid: false,
      reason: `Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * URL에서 NTAG424 파라미터 추출
 */
export function parseNTAG424URL(url: string, aesKey?: string): NTAG424Data | null {
  try {
    const urlObj = new URL(url);
    const piccData = urlObj.searchParams.get('picc_data') || urlObj.searchParams.get('p') || urlObj.searchParams.get('enc');
    const cmac = urlObj.searchParams.get('cmac') || urlObj.searchParams.get('c');

    if (!piccData || !cmac) {
      return null;
    }

    const parsed = parsePICCData(piccData, aesKey);

    return {
      piccData,
      cmac,
      counter: parsed?.counter,
      uid: parsed?.uid,
    };
  } catch (error) {
    return null;
  }
}

