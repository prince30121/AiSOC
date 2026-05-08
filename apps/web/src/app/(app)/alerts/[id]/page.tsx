import { AlertDetailView } from '@/components/alerts/AlertDetailView';

export const metadata = {
  title: 'Alert Detail | AiSOC',
};

export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <AlertDetailView alertId={id} />;
}
