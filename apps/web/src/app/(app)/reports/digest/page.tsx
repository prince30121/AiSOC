import { ExecutiveDigest } from '@/components/reports/ExecutiveDigest';

export const metadata = { title: 'Executive Digest — AiSOC' };

export default function ExecutiveDigestPage() {
  return (
    <div className="p-6 max-w-7xl mx-auto">
      <ExecutiveDigest />
    </div>
  );
}
