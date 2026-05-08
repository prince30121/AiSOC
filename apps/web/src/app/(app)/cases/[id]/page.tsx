import { CaseWorkspace } from '@/components/cases/CaseWorkspace';

interface CasePageProps {
  params: Promise<{ id: string }>;
}

export const metadata = {
  title: 'Case workspace | AiSOC',
};

export default async function CaseDetailPage({ params }: CasePageProps) {
  const { id } = await params;
  return <CaseWorkspace caseId={id} />;
}
