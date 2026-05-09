import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.mock('next/link', () => ({
  default: ({
    children,
    href,
    ...rest
  }: {
    children: React.ReactNode;
    href: string;
  } & Record<string, unknown>) => (
    <a href={href} {...(rest as Record<string, unknown>)}>
      {children}
    </a>
  ),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

vi.mock('framer-motion', () => {
  const factory = (Tag: React.ElementType) =>
    function MotionStub(props: Record<string, unknown>) {
      const { children, ...rest } = props as {
        children?: React.ReactNode;
      } & Record<string, unknown>;
      delete (rest as Record<string, unknown>).initial;
      delete (rest as Record<string, unknown>).animate;
      delete (rest as Record<string, unknown>).transition;
      delete (rest as Record<string, unknown>).whileHover;
      delete (rest as Record<string, unknown>).whileTap;
      return <Tag {...(rest as Record<string, unknown>)}>{children}</Tag>;
    };
  return {
    motion: new Proxy({}, { get: (_t, key: string) => factory(key as React.ElementType) }),
  };
});

vi.mock('react-hot-toast', () => ({
  default: { error: vi.fn(), success: vi.fn() },
}));

vi.mock('@/lib/api', () => ({
  authApi: {
    isAuthenticated: () => false,
    login: vi.fn(),
  },
}));

import { StartHero } from './StartHero';

describe('StartHero', () => {
  it('renders the three onboarding CTAs from WS-A2', () => {
    render(<StartHero />);

    // 1. Try the demo — silent demo login button.
    expect(screen.getByTestId('cta-try-demo')).toHaveTextContent(/Try the demo/i);

    // 2. Connect first source — links to /onboarding gallery.
    const connect = screen.getByTestId('cta-connect-source');
    expect(connect).toHaveTextContent(/Connect first source/i);
    expect(connect).toHaveAttribute('href', '/onboarding');

    // 3. Skip & explore — links to dashboard with the welcome querystring so
    //    the `DashboardWelcome` empty-state coach card mounts.
    const skip = screen.getByTestId('cta-skip');
    expect(skip).toHaveTextContent(/Skip & explore/i);
    expect(skip).toHaveAttribute('href', '/dashboard?welcome=1');
  });

  it('promises a working SOC instead of a blank dashboard', () => {
    render(<StartHero />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/3 minutes/i);
    // Buyer-value plan is explicit: every CTA must "land you in a working SOC,
    // not a blank dashboard." That promise is the page's contract.
    expect(screen.getByText(/working SOC, not a blank dashboard/i)).toBeInTheDocument();
  });
});
