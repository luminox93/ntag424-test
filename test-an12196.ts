import { verifyNTAG424 } from './lib/ntag424';

/**
 * 실제 태그 데이터로 테스트
 * - piccData: 9AA3D8DF06409B5AA4581429AE8C0611
 * - cmac: F9DAF12E0CFCF363
 * - Expected UID: 04623EBA1E1E90
 * - Expected Counter: 66
 */

async function testRealTag() {
  console.log('=== Testing Real Tag Data ===\n');

  // 사용자의 실제 태그 데이터
  const testData = {
    piccData: '9AA3D8DF06409B5AA4581429AE8C0611',
    cmac: 'F9DAF12E0CFCF363',
  };

  const aesKey = '00000000000000000000000000000000';

  console.log('Input:');
  console.log('- PICC Data:', testData.piccData);
  console.log('- CMAC:', testData.cmac);
  console.log('- AES Key:', aesKey);
  console.log();

  const result = await verifyNTAG424(testData, aesKey, true);

  console.log('\n=== Result ===');
  console.log(JSON.stringify(result, null, 2));

  console.log('\n=== Expected ===');
  console.log('- UID: 04623EBA1E1E90');
  console.log('- Counter: 66');
  console.log('- Valid: true');

  if (result.valid) {
    console.log('\n✅ SUCCESS! CMAC verification passed!');
  } else {
    console.log('\n❌ FAILED:', result.reason);
  }
}

testRealTag().catch(console.error);
