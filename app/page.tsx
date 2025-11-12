"use client";

import { useSession, signIn, signOut } from "next-auth/react";
import { useState } from "react";
import styles from "./page.module.css";

interface VerificationResult {
  success: boolean;
  message: string;
  reason?: string;
  data?: {
    uid?: string;
    counter?: number;
    user?: string;
    timestamp?: string;
  };
}

export default function Home() {
  const { data: session, status } = useSession();
  const [tagUrl, setTagUrl] = useState("");
  const [piccData, setPiccData] = useState("");
  const [cmac, setCmac] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [verificationHistory, setVerificationHistory] = useState<VerificationResult[]>([]);

  const handleVerify = async () => {
    if (!tagUrl && (!piccData || !cmac)) {
      alert("태그 URL 또는 PICC Data와 CMAC을 입력해주세요.");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("/api/verify-tag", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: tagUrl || undefined,
          piccData: piccData || undefined,
          cmac: cmac || undefined,
        }),
      });

      const data = await response.json();
      setResult(data);

      // 성공/실패 모두 히스토리에 추가
      setVerificationHistory(prev => [{...data, timestamp: new Date().toISOString()}, ...prev].slice(0, 10));
    } catch (error) {
      setResult({
        success: false,
        message: "검증 요청 실패",
        reason: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleTestReplayAttack = async () => {
    if (!result?.success) {
      alert("먼저 유효한 태그를 검증해주세요.");
      return;
    }

    alert("같은 데이터로 다시 검증을 시도합니다. 리플레이 공격이 감지되어야 합니다.");
    await handleVerify();
  };

  if (status === "loading") {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>로딩 중...</div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className={styles.container}>
        <div className={styles.loginCard}>
          <h1>NTAG424 Test</h1>
          <p>Google OAuth 로그인 후 NTAG424 태그 검증을 테스트할 수 있습니다.</p>
          <button onClick={() => signIn("google")} className={styles.loginButton}>
            <svg className={styles.googleIcon} viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            Sign in with Google
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.userInfo}>
          <img src={session.user?.image || ""} alt="Profile" className={styles.avatar} />
          <div>
            <div className={styles.userName}>{session.user?.name}</div>
            <div className={styles.userEmail}>{session.user?.email}</div>
          </div>
        </div>
        <button onClick={() => signOut()} className={styles.logoutButton}>
          로그아웃
        </button>
      </div>

      <main className={styles.main}>
        <h1 className={styles.title}>NTAG424 Tag Verification Test</h1>
        <p className={styles.subtitle}>리플레이 공격 방어 테스트</p>

        <div className={styles.card}>
          <h2>태그 데이터 입력</h2>

          <div className={styles.inputGroup}>
            <label>태그 URL (전체 URL)</label>
            <input
              type="text"
              value={tagUrl}
              onChange={(e) => setTagUrl(e.target.value)}
              placeholder="https://example.com?picc_data=...&cmac=..."
              className={styles.input}
            />
          </div>

          <div className={styles.divider}>또는</div>

          <div className={styles.inputGroup}>
            <label>PICC Data (Hex)</label>
            <input
              type="text"
              value={piccData}
              onChange={(e) => setPiccData(e.target.value)}
              placeholder="04E12345678910..."
              className={styles.input}
            />
          </div>

          <div className={styles.inputGroup}>
            <label>CMAC (Hex)</label>
            <input
              type="text"
              value={cmac}
              onChange={(e) => setCmac(e.target.value)}
              placeholder="ABCDEF1234567890"
              className={styles.input}
            />
          </div>

          <div className={styles.buttonGroup}>
            <button
              onClick={handleVerify}
              disabled={loading}
              className={styles.verifyButton}
            >
              {loading ? "검증 중..." : "태그 검증"}
            </button>

            {result?.success && (
              <button
                onClick={handleTestReplayAttack}
                className={styles.replayButton}
              >
                리플레이 공격 테스트
              </button>
            )}
          </div>
        </div>

        {result && (
          <div className={`${styles.card} ${styles.result} ${result.success ? styles.success : styles.error}`}>
            <h2>{result.success ? "✓ 검증 성공" : "✗ 검증 실패"}</h2>
            <p>{result.message}</p>
            {result.reason && (
              <p className={styles.reason}>
                <strong>사유:</strong> {result.reason}
              </p>
            )}
            {result.data && (
              <div className={styles.dataBox}>
                {result.data.uid && <div><strong>UID:</strong> {result.data.uid}</div>}
                {result.data.counter !== undefined && <div><strong>Counter:</strong> {result.data.counter}</div>}
                {result.data.user && <div><strong>User:</strong> {result.data.user}</div>}
                {result.data.timestamp && <div><strong>Time:</strong> {new Date(result.data.timestamp).toLocaleString('ko-KR')}</div>}
              </div>
            )}
          </div>
        )}

        {verificationHistory.length > 0 && (
          <div className={styles.card}>
            <h2>검증 히스토리</h2>
            <div className={styles.history}>
              {verificationHistory.map((item, index) => (
                <div key={index} className={`${styles.historyItem} ${item.success ? styles.historySuccess : styles.historyError}`}>
                  <div className={styles.historyHeader}>
                    <span className={styles.historyStatus}>
                      {item.success ? "✓ 성공" : "✗ 실패"}
                    </span>
                    <span className={styles.historyTime}>
                      {new Date(item.timestamp || Date.now()).toLocaleTimeString('ko-KR')}
                    </span>
                  </div>
                  {item.reason && <div className={styles.historyReason}>{item.reason}</div>}
                  {item.data?.counter !== undefined && (
                    <div className={styles.historyCounter}>Counter: {item.data.counter}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className={styles.info}>
          <h3>사용 방법</h3>
          <ol>
            <li>NTAG424 태그를 스캔하여 URL을 가져오거나 PICC Data와 CMAC을 직접 입력하세요.</li>
            <li>"태그 검증" 버튼을 클릭하여 태그의 유효성을 확인하세요.</li>
            <li>검증이 성공하면 "리플레이 공격 테스트" 버튼이 활성화됩니다.</li>
            <li>같은 데이터로 다시 검증을 시도하면 리플레이 공격이 감지됩니다.</li>
          </ol>
        </div>
      </main>
    </div>
  );
}
