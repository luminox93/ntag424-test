"use client";

import { useSession, signIn, signOut } from "next-auth/react";
import { useState, useEffect, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import styles from "./page.module.css";

interface VerificationResult {
  success: boolean;
  needsRegistration?: boolean;
  message: string;
  reason?: string;
  data?: {
    uid?: string;
    counter?: number;
    user?: string;
    timestamp?: string;
  };
}

function HomeContent() {
  const { data: session, status } = useSession();
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [showRegisterDialog, setShowRegisterDialog] = useState(false);
  const [userTags, setUserTags] = useState<string[]>([]);

  const piccData = searchParams.get('picc_data') || searchParams.get('p') || searchParams.get('enc');
  const cmac = searchParams.get('cmac') || searchParams.get('c');

  const verifyTag = useCallback(async () => {
    if (!piccData || !cmac) return;
    setLoading(true);
    setResult(null);

    try {
      console.log('Verifying tag with:', { piccData, cmac });
      const response = await fetch("/api/verify-tag", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ piccData, cmac }),
      });

      const data = await response.json();
      console.log('Verification result:', data);
      setResult(data);

      if (data.needsRegistration) {
        setShowRegisterDialog(true);
      }
    } catch (error) {
      console.error('Verification error:', error);
      setResult({
        success: false,
        message: "검증 요청 실패",
        reason: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setLoading(false);
    }
  }, [piccData, cmac]);

  // URL 파라미터 변경 시 result 초기화
  useEffect(() => {
    setResult(null);
    setShowRegisterDialog(false);
  }, [piccData, cmac]);

  useEffect(() => {
    if (piccData && cmac && session) {
      verifyTag();
    }
  }, [piccData, cmac, session, verifyTag]);

  useEffect(() => {
    if (session && !piccData && !cmac) {
      fetchUserTags();
    }
  }, [session, piccData, cmac]);

  const registerCurrentTag = async () => {
    if (!result?.data?.uid) return;
    console.log('Registering tag with UID:', result.data.uid);
    setLoading(true);
    setShowRegisterDialog(false);

    try {
      const response = await fetch("/api/register-tag", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid: result.data.uid }),
      });

      const data = await response.json();
      console.log('Registration result:', data);
      if (data.success) {
        await verifyTag();
      } else {
        alert(data.message || "태그 등록 실패");
      }
    } catch (error) {
      console.error('Registration error:', error);
      alert("태그 등록 요청 실패");
    } finally {
      setLoading(false);
    }
  };

  const fetchUserTags = async () => {
    try {
      const response = await fetch("/api/register-tag");
      const data = await response.json();
      if (data.success) {
        setUserTags(data.data.tags);
      }
    } catch (error) {
      console.error("Failed to fetch user tags:", error);
    }
  };

  if (status === "loading") {
    return <div className={styles.container}><div className={styles.loading}>로딩 중...</div></div>;
  }

  if ((piccData && cmac) && !session) {
    return (
      <div className={styles.container}>
        <div className={styles.loginCard}>
          <h1>NTAG424 인증 필요</h1>
          <p>태그에 접근하려면 Google 계정으로 로그인해주세요.</p>
          <button onClick={() => signIn("google")} className={styles.loginButton}>Sign in with Google</button>
        </div>
      </div>
    );
  }

  if ((piccData && cmac) && session) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <div className={styles.userInfo}>
            <div>
              <div className={styles.userName}>{session.user?.name}</div>
              <div className={styles.userEmail}>{session.user?.email}</div>
            </div>
          </div>
          <button onClick={() => signOut()} className={styles.logoutButton}>로그아웃</button>
        </div>
        <main className={styles.main}>
          <div style={{padding: '10px', background: '#f0f0f0', borderRadius: '5px', marginBottom: '10px', fontSize: '12px'}}>
            <div><strong>Status:</strong> {loading ? '검증 중...' : result ? (result.success ? '성공' : '실패') : '대기 중'}</div>
            <div><strong>piccData:</strong> {piccData?.substring(0, 20)}...</div>
            <div><strong>cmac:</strong> {cmac?.substring(0, 16)}</div>
          </div>
          {loading && <div className={styles.card}><div className={styles.loading}>검증 중...</div></div>}
          
          {showRegisterDialog && result?.needsRegistration && (
            <div className={styles.dialog}>
              <div className={styles.dialogContent}>
                <h2>태그 연결</h2>
                <p>이 태그를 내 계정에 연결하시겠습니까?</p>
                <div className={styles.dialogInfo}><strong>Tag UID:</strong> {result.data?.uid}</div>
                <div className={styles.dialogButtons}>
                  <button onClick={registerCurrentTag} className={styles.dialogButtonPrimary} disabled={loading}>연결하기</button>
                  <button onClick={() => setShowRegisterDialog(false)} className={styles.dialogButtonSecondary}>취소</button>
                </div>
              </div>
            </div>
          )}

          {result && !showRegisterDialog && (
            <>
              {result.success ? (
                <div className={styles.dashboard}>
                  <h1 className={styles.title}>✓ 접근 허용</h1>
                  <div className={styles.card}>
                    <h2>현재 태그 정보</h2>
                    <div className={styles.dataBox}>
                      <div><strong>Tag UID:</strong> {result.data?.uid}</div>
                      <div><strong>Counter:</strong> {result.data?.counter}</div>
                    </div>
                  </div>
                  <div className={styles.card}>
                    <h2>대시보드</h2>
                    <p>태그 인증에 성공했습니다.</p>
                  </div>
                </div>
              ) : (
                <div className={`${styles.card} ${styles.result} ${styles.error}`}>
                  <h2>✗ 접근 거부</h2>
                  <p><strong>메시지:</strong> {result.message}</p>
                  {result.reason && <p className={styles.reason}><strong>사유:</strong> {result.reason}</p>}
                  {result.data?.uid && <p><strong>UID:</strong> {result.data.uid}</p>}
                  {result.data?.counter !== undefined && <p><strong>Counter:</strong> {result.data.counter}</p>}
                  <details style={{marginTop: '10px', fontSize: '12px'}}>
                    <summary>디버그 정보</summary>
                    <pre style={{textAlign: 'left', overflow: 'auto'}}>{JSON.stringify({ piccData, cmac, result }, null, 2)}</pre>
                  </details>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    );
  }

  if (!session) {
    return (
      <div className={styles.container}>
        <div className={styles.loginCard}>
          <h1>NTAG424 Tag Manager</h1>
          <p>Google OAuth 로그인 후 NTAG424 태그를 관리할 수 있습니다.</p>
          <button onClick={() => signIn("google")} className={styles.loginButton}>Sign in with Google</button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.userInfo}>
          <div>
            <div className={styles.userName}>{session.user?.name}</div>
            <div className={styles.userEmail}>{session.user?.email}</div>
          </div>
        </div>
        <button onClick={() => signOut()} className={styles.logoutButton}>로그아웃</button>
      </div>
      <main className={styles.main}>
        <h1 className={styles.title}>내 태그 관리</h1>
        {userTags.length > 0 ? (
          <div className={styles.card}>
            <h2>연결된 태그 ({userTags.length}개)</h2>
            <div className={styles.tagList}>
              {userTags.map((tag, index) => <div key={index} className={styles.tagItem}><strong>UID:</strong> {tag}</div>)}
            </div>
          </div>
        ) : (
          <div className={styles.card}>
            <h2>연결된 태그가 없습니다</h2>
            <p>NFC 태그를 스캔하여 접속하면 자동으로 연결할 수 있습니다.</p>
          </div>
        )}
        <div className={styles.info}>
          <h3>사용 방법</h3>
          <ol>
            <li>NTAG424 태그를 스캔하면 URL이 생성됩니다.</li>
            <li>생성된 URL에 접속하면 자동으로 로그인 요청이 표시됩니다.</li>
            <li>로그인 후 태그가 미등록 상태면 연결 여부를 물어봅니다.</li>
            <li>연결된 태그로 접속하면 대시보드가 표시됩니다.</li>
          </ol>
        </div>
      </main>
    </div>
  );
}

export default function Home() {
  return (
    <Suspense fallback={<div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh'}}>로딩 중...</div>}>
      <HomeContent />
    </Suspense>
  );
}
