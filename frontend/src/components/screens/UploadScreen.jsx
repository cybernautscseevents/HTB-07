import React, { useState, useRef } from 'react';
import {
  UploadCloudIcon,
  FileTextIcon,
  CheckCircleIcon,
  AlertTriangleIcon,
  XIcon,
  RefreshCwIcon,
  ShieldIcon,
} from '../common/Icons';

import { validateSbomJson, uploadSbom } from '../../services/api';

export function UploadScreen({ onScanComplete, backendStatus }) {
  const [fileInfo, setFileInfo] = useState(null);
  const [validationError, setValidationError] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStep, setAnalysisStep] = useState(0);
  const [dragActive, setDragActive] = useState(false);

  const fileInputRef = useRef(null);
  const intervalRef = useRef(null);
  const timeoutRef = useRef(null);

  const steps = [
    'Reading SBOM document structure',
    'Validating CycloneDX / SPDX JSON specification',
    'Extracting component inventory & Package URLs (PURLs)',
    'Checking OSV & vulnerability intelligence feeds',
    'Evaluating contextual risk & dependency exposure',
    'Calculating SBOM trust score & NTIA quality metrics',
  ];

  const handleFileSelect = (selectedFile) => {
    if (!selectedFile) return;

    setValidationError(null);
    setFileInfo(null);

    const reader = new FileReader();

    reader.onload = (e) => {
      const content = e.target.result;

      const validation = validateSbomJson(content);

      if (validation.isValid) {
        setFileInfo({
          name: selectedFile.name,
          size: `${(selectedFile.size / 1024).toFixed(1)} KB`,
          format: `${validation.format} ${validation.version || ''}`.trim(),
          componentCount: validation.componentCount || 0,
          hasDependencies: validation.hasDependencies,
          rawContent: content,
        });
      } else {
        setValidationError(
          validation.error || 'Invalid SBOM format.'
        );

        setFileInfo({
          name: selectedFile.name,
          size: `${(selectedFile.size / 1024).toFixed(1)} KB`,
          format: 'Unrecognized / Non-standard JSON',
          rawContent: content,
        });
      }
    };

    reader.onerror = () => {
      setValidationError('Failed to read file contents.');
      setFileInfo(null);
    };

    reader.readAsText(selectedFile);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();

    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    }

    if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();

    setDragActive(false);

    if (
      e.dataTransfer.files &&
      e.dataTransfer.files.length > 0
    ) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleRemoveFile = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }

    setFileInfo(null);
    setValidationError(null);
    setIsAnalyzing(false);
    setAnalysisStep(0);

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const startProgressAnimation = () => {
    setAnalysisStep(0);

    intervalRef.current = setInterval(() => {
      setAnalysisStep((previousStep) => {
        if (previousStep < steps.length - 1) {
          return previousStep + 1;
        }

        return previousStep;
      });
    }, 700);
  };

  const stopProgressAnimation = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  };

  const startAnalysis = async () => {
    if (!fileInfo || validationError || isAnalyzing) {
      return;
    }

    if (!fileInfo.rawContent) {
      setValidationError('SBOM file content is unavailable.');
      return;
    }

    setIsAnalyzing(true);
    setValidationError(null);

    startProgressAnimation();

    try {
      const file = new File(
        [fileInfo.rawContent],
        fileInfo.name,
        {
          type: 'application/json',
        }
      );

      /*
       * Real backend request.
       *
       * The backend should:
       * 1. Parse the uploaded SBOM
       * 2. Validate CycloneDX/SPDX
       * 3. Extract components and PURLs
       * 4. Query OSV
       * 5. Calculate risk
       * 6. Calculate trust score
       * 7. Return the complete scan result
       */
      const result = await uploadSbom(file);

      stopProgressAnimation();

      if (!result || !result.success) {
        throw new Error(
          result?.error ||
            result?.message ||
            'The backend rejected the SBOM.'
        );
      }

      if (!result.data) {
        throw new Error(
          'The backend returned an empty scan result.'
        );
      }

      /*
       * Finish the visual progress.
       */
      setAnalysisStep(steps.length - 1);

      timeoutRef.current = setTimeout(() => {
        setIsAnalyzing(false);

        /*
         * Pass the REAL backend response to the parent.
         * No fabricated vulnerabilities, scores, components,
         * or demo values are created here.
         */
        onScanComplete({
          ...result.data,
          sourceSbom: fileInfo.rawContent,

          fileName:
            result.data.fileName ||
            result.data.file_name ||
            fileInfo.name,

          format:
            result.data.format ||
            fileInfo.format,

          componentsCount:
            result.data.componentsCount ??
            result.data.components_count ??
            result.data.summary?.totalComponents ??
            result.data.summary?.total_components ??
            fileInfo.componentCount,
        });
      }, 700);
    } catch (error) {
      stopProgressAnimation();

      setIsAnalyzing(false);
      setAnalysisStep(0);

      setValidationError(
        error?.message ||
          'SBOM analysis failed. Please make sure the backend is running.'
      );
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12">

      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">
          Analyze an SBOM
        </h2>

        <p className="text-xs text-slate-400 mt-1">
          Upload a CycloneDX or SPDX SBOM to evaluate vulnerabilities,
          risk context, and SBOM quality.
        </p>
      </div>

      {/* Upload Box */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-8 space-y-6">

        {!fileInfo ? (

          /* Dropzone */
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${
              dragActive
                ? 'border-blue-500 bg-blue-500/10'
                : 'border-[#22304d] hover:border-blue-500/50 bg-[#0d1320]/60'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.spdx,.cdx"
              onChange={(e) => {
                handleFileSelect(e.target.files?.[0]);
              }}
              className="hidden"
            />

            <div className="w-16 h-16 rounded-full bg-blue-600/15 border border-blue-500/30 text-blue-400 flex items-center justify-center mx-auto mb-4">
              <UploadCloudIcon className="w-8 h-8 text-blue-400" />
            </div>

            <h3 className="text-sm font-bold text-slate-200">
              Drag and drop your SBOM file here, or browse
            </h3>

            <p className="text-xs text-slate-400 mt-1">
              Supports CycloneDX JSON (1.3, 1.4, 1.5) and SPDX JSON (2.2, 2.3)
            </p>

            <div className="mt-4 flex items-center justify-center gap-3">
              <span className="text-[11px] px-2.5 py-1 rounded bg-[#151e33] border border-[#1f2c4a] text-slate-400 font-mono-tech">
                .json
              </span>

              <span className="text-[11px] px-2.5 py-1 rounded bg-[#151e33] border border-[#1f2c4a] text-slate-400 font-mono-tech">
                CycloneDX
              </span>

              <span className="text-[11px] px-2.5 py-1 rounded bg-[#151e33] border border-[#1f2c4a] text-slate-400 font-mono-tech">
                SPDX
              </span>
            </div>
          </div>

        ) : (

          /* File Selected */
          <div className="space-y-6">

            <div className="p-4 rounded-xl bg-[#0d1320] border border-[#1c2742] flex items-center justify-between">

              <div className="flex items-center gap-4">

                <div className="w-12 h-12 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
                  <FileTextIcon className="w-6 h-6" />
                </div>

                <div>
                  <div className="text-sm font-bold text-slate-100 font-mono-tech">
                    {fileInfo.name}
                  </div>

                  <div className="text-xs text-slate-400 flex items-center gap-3 mt-1">

                    <span>
                      Size: {fileInfo.size}
                    </span>

                    <span>•</span>

                    <span className="text-blue-400 font-mono-tech">
                      {fileInfo.format}
                    </span>

                    {fileInfo.componentCount > 0 && (
                      <>
                        <span>•</span>

                        <span>
                          {fileInfo.componentCount} Components
                        </span>
                      </>
                    )}

                  </div>
                </div>

              </div>

              {!isAnalyzing && (
                <button
                  type="button"
                  onClick={handleRemoveFile}
                  className="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                  title="Remove file"
                >
                  <XIcon className="w-5 h-5" />
                </button>
              )}

            </div>

            {/* Validation Feedback */}
            {validationError ? (

              <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-start gap-3">

                <AlertTriangleIcon className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />

                <div>
                  <div className="font-bold text-red-200">
                    Unable to analyze this SBOM
                  </div>

                  <div className="mt-1">
                    {validationError}
                  </div>

                  {!isAnalyzing && (
                    <button
                      type="button"
                      onClick={handleRemoveFile}
                      className="mt-3 text-red-400 hover:underline font-semibold"
                    >
                      Select another file
                    </button>
                  )}
                </div>

              </div>

            ) : (

              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-2">

                <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />

                <span>
                  Format verified: Valid {fileInfo.format} standard structure detected.
                </span>

              </div>

            )}

            {/* Analysis Stepper */}
            {isAnalyzing && (

              <div className="p-5 rounded-xl bg-[#090e18] border border-blue-500/30 space-y-4">

                <div className="flex items-center justify-between">

                  <div className="flex items-center gap-2 text-xs font-bold text-blue-400 font-mono-tech">

                    <RefreshCwIcon className="w-4 h-4 animate-spin text-blue-400" />

                    <span>
                      Analyzing SBOM Security & Trust Posture...
                    </span>

                  </div>

                  <span className="text-xs font-mono-tech text-slate-400">
                    Step {analysisStep + 1} of {steps.length}
                  </span>

                </div>

                <div className="space-y-2 pt-2">

                  {steps.map((stepText, idx) => {

                    const isDone = idx < analysisStep;
                    const isCurrent = idx === analysisStep;

                    return (
                      <div
                        key={idx}
                        className={`flex items-center gap-3 text-xs font-mono-tech transition-opacity ${
                          isDone
                            ? 'text-emerald-400'
                            : isCurrent
                            ? 'text-blue-300 font-semibold'
                            : 'text-slate-400 opacity-40'
                        }`}
                      >

                        {isDone ? (

                          <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />

                        ) : isCurrent ? (

                          <span className="w-4 h-4 rounded-full border-2 border-blue-400 border-t-transparent animate-spin shrink-0" />

                        ) : (

                          <span className="w-4 h-4 rounded-full border border-slate-700 shrink-0 inline-block" />

                        )}

                        <span>
                          {stepText}
                        </span>

                      </div>
                    );
                  })}

                </div>

              </div>
            )}

            {/* Action Buttons */}
            {!isAnalyzing && !validationError && (

              <div className="flex items-center justify-end gap-3 pt-2">

                <button
                  type="button"
                  onClick={handleRemoveFile}
                  className="px-4 py-2 rounded-lg bg-[#141b2e] hover:bg-[#1a243c] text-slate-300 text-xs font-semibold transition-colors"
                >
                  Cancel
                </button>

                <button
                  type="button"
                  onClick={startAnalysis}
                  className="px-6 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-blue-600/30 transition-colors"
                >
                  Analyze SBOM
                </button>

              </div>
            )}

          </div>
        )}

      </div>

      {/* Architecture Disclosure */}
      <div className="p-4 rounded-xl bg-[#0d121f] border border-[#182236] text-xs text-slate-400 space-y-2">

        <div className="flex items-center justify-between">

          <div className="font-semibold text-slate-300 font-mono-tech flex items-center gap-1.5">

            <ShieldIcon className="w-3.5 h-3.5 text-blue-400" />

            <span>
              Security Intelligence Pipeline Details
            </span>

          </div>

          <span
            className={`text-[10px] font-mono-tech px-2 py-0.5 rounded border ${
              backendStatus?.isOnline
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-red-500/10 text-red-400 border-red-500/30'
            }`}
          >
            Backend:{' '}
            {backendStatus?.isOnline
              ? 'Online'
              : 'Offline'}
          </span>

        </div>

        <p className="text-[11px] text-slate-400">
          The auditor extracts component PURLs and queries vulnerability
          intelligence feeds. Risk calculations use the results returned
          by the backend. Dependency graphs and SBOM metadata are evaluated
          from the uploaded document without generating fabricated findings.
        </p>

      </div>

    </div>
  );
}

export default UploadScreen;