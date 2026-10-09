import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewScreen } from './components/screens/OverviewScreen';
import { UploadScreen } from './components/screens/UploadScreen';
import { ScansScreen } from './components/screens/ScansScreen';
import { VulnerabilitiesScreen } from './components/screens/VulnerabilitiesScreen';
import { VulnerabilityDetailScreen } from './components/screens/VulnerabilityDetailScreen';
import { ComponentsScreen } from './components/screens/ComponentsScreen';
import { SbomQualityScreen } from './components/screens/SbomQualityScreen';
import { ReportsScreen } from './components/screens/ReportsScreen';
import { SbomComparisonScreen } from './components/screens/SbomComparisonScreen';
import { SettingsScreen } from './components/screens/SettingsScreen';
import { AuthScreen } from './components/auth/AuthScreen';

import { checkBackendHealth, getCurrentUser, getScans, getScan, logout, generateUpdatedSbom } from './services/api';
import { normalizeScanData } from './services/normalizeScan';

export default function App() {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState('');
  const [currentTab, setCurrentTab] = useState('overview');
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);

  // Real backend data only
  const [scanData, setScanData] = useState(null);
  const [updatedSbom, setUpdatedSbom] = useState(null);
  const [updatedSbomLoading, setUpdatedSbomLoading] = useState(false);
  const [updatedSbomError, setUpdatedSbomError] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [components, setComponents] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);

  const [backendStatus, setBackendStatus] = useState({
    isOnline: false,
    osvConnected: false,
    message: 'Connecting...',
  });

  const [searchQuery, setSearchQuery] = useState('');
  const [vulnSearchPreset, setVulnSearchPreset] = useState('');

  const refreshBackendStatus = async () => {
    const status = await checkBackendHealth();
    setBackendStatus(status);
  };

  const getLatestScanData = async (scans) => {
    if (!scans.length) return null;
    return normalizeScanData(await getScan(scans[0].id));
  };

  const setActiveScan = (scan) => {
    if (!scan) return;
    setScanData(scan);
    setVulnerabilities(scan.vulnerabilities);
    setComponents(scan.components);
    setCurrentTab('overview');
  };

  // Restore the server-side session before requesting any private scan data.
  useEffect(() => {
    let isMounted = true;

    const restoreSession = async () => {
      try {
        const currentUser = await getCurrentUser();
        if (!isMounted) return;
        if (currentUser) {
          const [status, scans] = await Promise.all([checkBackendHealth(), getScans()]);
          let latestScan = null;
          let scanRestoreError = '';
          try {
            latestScan = await getLatestScanData(scans);
          } catch (error) {
            scanRestoreError = `Could not restore the latest scan: ${error.message}`;
          }
          if (!isMounted) return;
          setUser(currentUser);
          setBackendStatus({ ...status, isOnline: true });
          setScanHistory(scans);
          setActiveScan(latestScan);
          if (scanRestoreError) setAuthError(scanRestoreError);
        }
      } catch (error) {
        if (isMounted) setAuthError(error.message);
      } finally {
        if (isMounted) setAuthLoading(false);
      }
    };

    restoreSession();

    return () => {
      isMounted = false;
    };
  }, []);

  const handleAuthenticated = async (authenticatedUser) => {
    const [status, scans] = await Promise.all([checkBackendHealth(), getScans()]);
    let latestScan = null;
    let scanRestoreError = '';
    try {
      latestScan = await getLatestScanData(scans);
    } catch (error) {
      scanRestoreError = `Could not restore the latest scan: ${error.message}`;
    }
    setBackendStatus({ ...status, isOnline: true });
    setScanHistory(scans);
    setActiveScan(latestScan);
    setUser(authenticatedUser);
    setAuthError(scanRestoreError);
  };

  const handleLogout = async () => {
    try {
      await logout();
      setUser(null);
      setScanData(null);
      setUpdatedSbom(null);
      setUpdatedSbomLoading(false);
      setUpdatedSbomError('');
      setVulnerabilities([]);
      setComponents([]);
      setScanHistory([]);
      setCurrentTab('overview');
      setSelectedVulnerability(null);
      setAuthError('');
    } catch (error) {
      setAuthError(error.message);
    }
  };

  // Select vulnerability
  const handleSelectVulnerability = (vuln) => {
    setSelectedVulnerability(vuln);
    setCurrentTab('detail');
  };

  // Back to vulnerabilities
  const handleBackToVulnerabilities = () => {
    setCurrentTab('vulnerabilities');
  };

  // Filter vulnerabilities by package
  const handleFilterByPackage = (packageName) => {
    setVulnSearchPreset(packageName);
    setCurrentTab('vulnerabilities');
  };

  // Handle real scan completion from backend
  const handleScanComplete = (scanInfo) => {
    if (!scanInfo) return;

    const { sourceSbom, ...scanResult } = scanInfo;
    const normalizedScan = normalizeScanData(scanResult);
    setActiveScan(normalizedScan);
    setUpdatedSbom(null);
    setUpdatedSbomError('');
    setUpdatedSbomLoading(true);
    generateUpdatedSbom(
      scanResult.fileName || 'sbom.json',
      sourceSbom,
      scanResult.findings || [],
    )
      .then(setUpdatedSbom)
      .catch((error) => setUpdatedSbomError(error.message || 'Could not prepare the updated SBOM.'))
      .finally(() => setUpdatedSbomLoading(false));
    getScans()
      .then(setScanHistory)
      .catch((error) => console.error('Failed to refresh scan history.', error));

    setCurrentTab('overview');
  };

  // Load a historical scan returned by the backend
  const handleSelectHistoricalScan = async (scan) => {
    if (!scan) return;

    try {
      const normalizedScan = normalizeScanData(await getScan(scan.id));
      setActiveScan(normalizedScan);
      setUpdatedSbom(null);
      setUpdatedSbomLoading(false);
      setUpdatedSbomError('');
    } catch (error) {
      console.error('Failed to load the selected SBOM scan.', error);
    }
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#090d16] flex items-center justify-center text-sm text-slate-400">
        Checking your secure session…
      </div>
    );
  }

  if (!user) {
    return <AuthScreen onAuthenticated={handleAuthenticated} initialError={authError} />;
  }

  return (
    <div className="flex w-full min-h-screen bg-[#090d16] text-slate-100 font-sans selection:bg-blue-600 selection:text-white">

      {/* Persistent Desktop Sidebar */}
      <Sidebar
        currentTab={currentTab}
        setTab={(tab) => {
          if (tab !== 'detail') {
            setSelectedVulnerability(null);
          }

          setCurrentTab(tab);
        }}
        scanData={scanData}
        backendStatus={backendStatus}
        user={user}
        onLogout={handleLogout}
      />

      {/* Main Desktop Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">

        {/* Top Desktop Header */}
        <Header
          currentTab={currentTab}
          scanData={scanData}
          searchQuery={searchQuery}
          setSearchQuery={(q) => {
            setSearchQuery(q);

            if (
              q.trim().length > 1 &&
              currentTab !== 'vulnerabilities' &&
              currentTab !== 'components'
            ) {
              setVulnSearchPreset(q);
              setCurrentTab('vulnerabilities');
            }
          }}
          onNewScanClick={() => setCurrentTab('upload')}
        />

        {/* Scrollable View Container */}
        <main className="flex-1 overflow-y-auto px-8 py-6 w-full max-w-[1920px] mx-auto">
          {authError && (
            <p role="alert" className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              {authError}
            </p>
          )}

          {currentTab === 'overview' && (
            <OverviewScreen
              scanData={scanData}
              updatedSbom={updatedSbom}
              updatedSbomLoading={updatedSbomLoading}
              updatedSbomError={updatedSbomError}
              vulnerabilities={vulnerabilities}
              onSelectVulnerability={handleSelectVulnerability}
              onNavigateTab={setCurrentTab}
            />
          )}

          {currentTab === 'upload' && (
            <UploadScreen
              onScanComplete={handleScanComplete}
              backendStatus={backendStatus}
            />
          )}

          {currentTab === 'scans' && (
            <ScansScreen
              onNewScan={() => setCurrentTab('upload')}
              scans={scanHistory}
              onSelectScan={handleSelectHistoricalScan}
              currentScanId={scanData?.id}
            />
          )}

          {currentTab === 'vulnerabilities' && (
            <VulnerabilitiesScreen
              vulnerabilities={vulnerabilities}
              scanData={scanData}
              onSelectVulnerability={handleSelectVulnerability}
              initialSearchQuery={vulnSearchPreset || searchQuery}
            />
          )}

          {currentTab === 'detail' && (
            <VulnerabilityDetailScreen
              vulnerability={selectedVulnerability}
              onBack={handleBackToVulnerabilities}
            />
          )}

          {currentTab === 'components' && (
            <ComponentsScreen
              components={components}
              onSelectComponent={(component) =>
                handleFilterByPackage(component.name)
              }
              onFilterVulnerabilitiesByPackage={
                handleFilterByPackage
              }
            />
          )}

          {currentTab === 'quality' && (
            <SbomQualityScreen
              scanData={scanData}
              onReviewUncertainFindings={() => {
                setVulnSearchPreset('UNKNOWN');
                setCurrentTab('vulnerabilities');
              }}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsScreen
              scanData={scanData}
              vulnerabilities={vulnerabilities}
              components={components}
            />
          )}

          {currentTab === 'comparison' && <SbomComparisonScreen />}

          {currentTab === 'settings' && (
            <SettingsScreen
              backendStatus={backendStatus}
              onRefreshBackendStatus={refreshBackendStatus}
            />
          )}

        </main>
      </div>
    </div>
  );
}