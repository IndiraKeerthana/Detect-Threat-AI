import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { RefreshCw, Home, AlertTriangle } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
}

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = {
    hasError: false,
    error: null,
  };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // Keep detailed error information in the developer console only.
    // Never expose stack traces or internal paths in the user-facing UI.
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  reset = (): void => {
    this.setState({
      hasError: false,
      error: null,
    });

    this.props.onReset?.();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="surface-card p-12 max-w-2xl mx-auto my-8 border border-[#2a3242] rounded-lg space-y-6 text-center">
          <div className="w-16 h-16 rounded bg-[#261114] border border-[#5c1d24] mx-auto flex items-center justify-center">
            <AlertTriangle className="w-8 h-8 text-[#ef4444]" />
          </div>

          <div className="space-y-2">
            <h2 className="text-lg font-bold font-mono tracking-wider text-[#f1f5f9] uppercase">
              Something went wrong
            </h2>

            <p className="text-sm text-[#94a3b8] font-sans leading-relaxed">
              The investigation view encountered an unexpected UI error.
              This is a client-side rendering issue. Your forensic data is safe
              on the server.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={this.reset}
              className="px-5 py-2.5 rounded bg-[#8b5cf6] hover:bg-[#7c3aed] text-white text-xs font-mono font-medium inline-flex items-center gap-2 transition-colors shadow-sm"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Try Again
            </button>

            <button
              type="button"
              onClick={() => {
                window.location.href = '/';
              }}
              className="px-5 py-2.5 rounded bg-[#171b23] hover:bg-[#1e232e] text-[#f1f5f9] border border-[#2a3242] text-xs font-mono inline-flex items-center gap-2 transition-colors"
            >
              <Home className="w-3.5 h-3.5" />
              Return to Intake Console
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;