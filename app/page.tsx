"use client";

import { useSession, signIn, signOut } from "next-auth/react";
import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
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

function HomeContent() {
  const { data: session, status } = useSession();
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [registrationUid, setRegistrationUid] = useState("");
  const [userTags, setUserTags] = useState<string[]>([]);

  const piccData = searchParams.get('picc_data') || searchParams.get('p');
  const cmac = searchParams.get('cmac') || searchParams.get('c');

  useEffect(() => {
    if (piccData && cmac && session && !loading && !result) {
      verifyTag();
    }
  }, [piccData, cmac, session]);

  useEffect(() => {
    if (session && !piccData && !cmac) {
      fetchUserTags();
    }
  }, [session, piccData, cmac]);

  const verifyTag = async () => {
    if (!piccData || !cmac) return;
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("/api/verify-tag", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ piccData, cmac }),
      });

      const data = await response.json();
      setResult(data);
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

  const registerTag = async () => {
    if (!registrationUid) {
      alert("태그 UID를 입력해주세요.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("/api/register-tag", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid: registrationUid }),
      });

      const data = await response.json();
      if (data.success) {
        alert("태그가 성공적으로 등록되었습니다!");
        setRegistrationUid("");
        fetchUserTags();
      } else {
        alert(data.message || "태그 등록 실패");
      }
    } catch (error) {
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
    return (
      <div className={styles.container}>
        <div className={styles.loading}>로딩 중...</div>
      </div>
    );
  }

  if ((piccData && cmac) && !session) {
    return (
      <div className={styles.container}>
        <div className={styles.loginCard}>
          <h1>NTAG424 인증 필요</h1>
          <p>태그에 접근하려면 Google 계정으로 로그인해주세요.</p>
          <button onClick={() => signIn("google")} className={styles.loginButton}>
            Sign in with Google
          </button>
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
          <button onClick={() => signOut()} className={styles.logoutButton}>
            로그아웃
          </button>
        </div>
        <main className={styles.main}>
          <h1 className={styles.title}>NTAG424 Tag Verification</h1>
          {loading && (
            <div className={styles.card}>
              <div className={styles.loading}>검증 중...</div>
            </div>
          )}
          {result && (
            <div className={`${styles.card} ${styles.result} ${result.success ? styles.success : styles.error}`}>
              <h2>{result.success ? "✓ 접근 허용" : "✗ 접근 거부"}</h2>
              <p>{result.message}</p>
              {result.reason && (
                <p className={styles.reason}>
                  <strong>사유:</strong> {result.reason}
                </p>
              )}
              {result.data && (
                <div className={styles.dataBox}>
                  {result.data.uid && <div><strong>Tag UID:</strong> {result.data.uid}</div>}
                  {result.data.counter !== undefined && <div><strong>Counter:</strong> {result.data.counter}</div>}
                </div>
              )}
            </div>
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
          <button onClick={() => signIn("google")} className={styles.loginButton}>
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
        <h1 className={styles.title}>NTAG424 Tag Manager</h1>
        <div className={styles.card}>
          <h2>새 태그 등록</h2>
          <div className={styles.inputGroup}>
            <label>태그 UID</label>
            <input
              type="text"
              value={registrationUid}
              onChange={(e) => setRegistrationUid(e.target.value)}
              placeholder="04E12345678910"
              className={styles.input}
            />
          </div>
          <button onClick={registerTag} disabled={loading} className={styles.verifyButton}>
            {loading ? "등록 중..." : "태그 등록"}
          </button>
        </div>
        {userTags.length > 0 && (
          <div className={styles.card}>
            <h2>내 태그 목록 ({userTags.length}개)</h2>
            <div className={styles.tagList}>
              {userTags.map((tag, index) => (
                <div key={index} className={styles.tagItem}>
                  <strong>UID:</strong> {tag}
                </div>
              ))}
            </div>
          </div>
        )}
        <div className={styles.info}>
          <h3>사용 방법</h3>
          <ol>
            <li>NTAG424 태그의 UID를 위에 입력하여 등록하세요.</li>
            <li>태그를 스캔하면 URL이 생성됩니다.</li>
            <li>해당 URL에 접속하면 자동으로 태그 검증이 진행됩니다.</li>
            <li>등록된 태그이고 리플레이 공격이 아니면 접근이 허용됩니다.</li>
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
