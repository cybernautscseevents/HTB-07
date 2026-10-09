import React, { useState } from 'react';
import { authenticate } from '../../services/api';
import { CheckCircleIcon, PackageIcon, ShieldIcon, ShieldAlertIcon } from '../common/Icons';

export function AuthScreen({ onAuthenticated, initialError = '' }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(initialError);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setPending(true);
    setError('');
    try {
      const user = await authenticate(email, password, mode);
      await onAuthenticated(user);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setPending(false);
    }
  };

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#090d16] px-4 py-10 text-slate-100 sm:px-6 lg:py-14">
      <div className="pointer-events-none absolute -left-40 top-0 h-96 w-96 rounded-full bg-blue-600/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-40 bottom-0 h-96 w-96 rounded-full bg-cyan-500/[0.07] blur-3xl" />
      <div className="relative grid w-full max-w-6xl items-center gap-10 lg:grid-cols-[minmax(0,1fr)_440px] lg:gap-16">
        <section className="mx-auto w-full max-w-xl">
          <div className="mb-8 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-blue-500/30 bg-blue-600/15">
              <ShieldIcon className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-400">SBOM Risk &amp; Trust Auditor</p>
              <p className="mt-1 text-xs text-slate-500">Software supply-chain visibility</p>
            </div>
          </div>

          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">Understand your software risk</p>
          <h1 className="max-w-lg text-3xl font-bold leading-tight tracking-tight text-white sm:text-4xl lg:text-5xl">
            See what your software depends on.
            <span className="mt-1 block text-blue-400">Know what needs attention.</span>
          </h1>
          <p className="mt-5 max-w-xl text-sm leading-6 text-slate-400 sm:text-base">
            Upload a CycloneDX or SPDX SBOM to review its components, check for known vulnerabilities, and get a clearer picture of software supply-chain risk.
          </p>

          <div className="mt-8 grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
            {[
              {
                Icon: PackageIcon,
                title: 'Explore your components',
                description: 'See the packages and dependency relationships listed in your SBOM.',
                color: 'text-cyan-300',
                tint: 'bg-cyan-400/10',
              },
              {
                Icon: ShieldAlertIcon,
                title: 'Review known vulnerabilities',
                description: 'Check component versions against OSV vulnerability data.',
                color: 'text-amber-300',
                tint: 'bg-amber-400/10',
              },
              {
                Icon: CheckCircleIcon,
                title: 'Prioritize next steps',
                description: 'Use risk context, SBOM quality checks, and exportable reports.',
                color: 'text-emerald-300',
                tint: 'bg-emerald-400/10',
              },
            ].map(({ Icon, title, description, color, tint }) => (
              <div key={title} className="flex gap-3 rounded-xl border border-[#1b253b] bg-[#101726]/75 p-4">
                <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${tint}`}>
                  <Icon className={`h-5 w-5 ${color}`} />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
                  <p className="mt-1 text-xs leading-5 text-slate-400">{description}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 hidden items-center gap-2 text-xs text-slate-500 sm:flex">
            <span className="rounded-md border border-[#253659] bg-[#101726] px-2.5 py-1.5">CycloneDX</span>
            <span className="text-slate-600">+</span>
            <span className="rounded-md border border-[#253659] bg-[#101726] px-2.5 py-1.5">SPDX</span>
            <span className="ml-1">SBOM formats supported</span>
          </div>
        </section>

        <section className="mx-auto w-full max-w-md rounded-2xl border border-[#1b253b] bg-[#101726] p-7 shadow-2xl sm:p-8 lg:col-start-2 lg:row-start-1">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-blue-500/30 bg-blue-600/15">
              <ShieldIcon className="h-6 w-6 text-blue-400" />
            </div>
            <h1 className="text-2xl font-bold">{mode === 'login' ? 'Welcome back' : 'Create your account'}</h1>
            <p className="mt-2 text-sm text-slate-400">
              {mode === 'login' ? 'Sign in to access your SBOM risk dashboard.' : 'Get started with your first SBOM review.'}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
          <label className="block space-y-2">
            <span className="text-xs font-semibold text-slate-300">Email address</span>
            <input
              type="email"
              name="email"
              autoComplete="email"
              required
              maxLength={254}
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full rounded-lg border border-[#253659] bg-[#0d1320] px-3 py-3 text-sm outline-none transition focus:border-blue-500"
              placeholder="you@company.com"
            />
          </label>

          <label className="block space-y-2">
            <span className="text-xs font-semibold text-slate-300">Password</span>
            <input
              type="password"
              name="password"
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              required
              minLength={mode === 'register' ? 8 : undefined}
              maxLength={72}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-lg border border-[#253659] bg-[#0d1320] px-3 py-3 text-sm outline-none transition focus:border-blue-500"
              placeholder={mode === 'register' ? 'At least 8 characters' : 'Enter your password'}
            />
            {mode === 'register' && (
              <span className="block text-[11px] text-slate-500">Use at least 8 characters; passwords are limited to 72 UTF-8 bytes.</span>
            )}
          </label>

          {error && <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</p>}

          <button
            type="submit"
            disabled={pending}
            className="w-full rounded-lg bg-blue-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-wait disabled:opacity-60"
          >
            {pending ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
          </form>

          <p className="mt-6 text-center text-sm text-slate-400">
            {mode === 'login' ? 'New to the auditor?' : 'Already have an account?'}{' '}
            <button
              type="button"
              onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); }}
              className="font-semibold text-blue-400 hover:text-blue-300"
            >
              {mode === 'login' ? 'Create an account' : 'Sign in'}
            </button>
          </p>
          <p className="mt-5 text-center text-[11px] leading-relaxed text-slate-500">
            Your password is securely hashed on the backend. Authentication uses an HttpOnly session cookie.
          </p>
        </section>
      </div>
    </main>
  );
}
