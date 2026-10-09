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
import { SettingsScreen } from './components/screens/SettingsScreen';

import { checkBackendHealth } from './services/api';

// The backend returns the vulnerability list as `findings`.
// Older code used `vulnerabilities`, so we accept both.
function normalizeScan(raw) {
  if (!raw) return null;

  // In case the response is wrapped, e.g. { success: true, data: {...} }
  const scan = raw.data && !raw.findings && !raw.summary ? raw.data : raw;

  return {
    ...scan,
    // Keep a scanId alias because older UI code used it (backend sends `id`)
    scanId: scan.scanId || scan.id,
    findings: scan.findings || scan.vulnerabilities || [],
    components: scan.components || [],
  };
}

export default function App() {
  const [currentTab, setCurrentTab] = useState('overview');
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);

  // Real backend data only
  const [scanData, setScanData] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [components, setComponents] = useState([]);

  const [backendStatus, setBackendStatus] = useState({
    isOnline: false,
    message: 'Connecting...',
  });

  const [searchQuery, setSearchQuery] = useState('');
  const [vulnSearchPreset, setVulnSearchPreset] = useState('');

  const refreshBackendStatus = async () => {
    const status = await checkBackendHealth();
    setBackendStatus(status);
  };

  // Check backend when application starts
  useEffect(() => {
    let isMounted = true;

    checkBackendHealth().then((status) => {
      if (isMounted) {
        setBackendStatus(status);
      }
    });

    return () => {
      isMounted = false;
    };
  }, []);

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

  // Shared logic for loading a scan into state
  const loadScan = (rawScan) => {
    const scan = normalizeScan(rawScan);
    if (!scan) return;

    // Helpful while debugging: see exactly what the backend sent
    console.log('Scan loaded:', scan);

    setScanData(scan);
    setVulnerabilities(scan.findings);
    setComponents(scan.components);
    setCurrentTab('overview');
  };

  // Handle real scan completion from backend
  const handleScanComplete = (scanInfo) => {
    loadScan(scanInfo);
  };

  // Load a historical scan returned by the backend
  const handleSelectHistoricalScan = (scan) => {
    loadScan(scan);
  };

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

          {currentTab === 'overview' && (
            <OverviewScreen
              scanData={scanData}
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
              onSelectScan={handleSelectHistoricalScan}
              currentScanId={scanData?.scanId || scanData?.id}
            />
          )}

          {currentTab === 'vulnerabilities' && (
            <VulnerabilitiesScreen
              vulnerabilities={vulnerabilities}
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
