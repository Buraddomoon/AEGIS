import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, it, vi } from 'vitest'
import { CoveragePage } from './Operations'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

it('keeps comparison selectors fixed until the matching historical response arrives', async () => {
  let finish!: (value: unknown) => void
  const delayed = new Promise((resolve) => {
    finish = resolve
  })
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string) => ({
      ok: true,
      status: 200,
      json: async () =>
        path.includes('/coverage/compare')
          ? delayed
          : path.includes('/catalog/attack/releases')
            ? { items: [], total: 0 }
            : path.includes('/coverage/runs')
              ? {
                  items: [
                    { id: 'first', campaign_id: 'same', created_at: '2026-10-22T12:00:00Z' },
                    { id: 'later', campaign_id: 'same', created_at: '2026-10-22T13:00:00Z' },
                  ],
                  total: 2,
                  scope_sha256: 'a'.repeat(64),
                }
              : {
                  catalogued_techniques: 706,
                  evaluated_techniques: 0,
                  total_runs: 2,
                  completed_tests: 0,
                  valid_tests: 0,
                  detected_percentage: null,
                  outcomes: {},
                  denominator: 'Testes válidos',
                  limitation: 'Demo sintético',
                },
    })),
  )
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <CoveragePage />
    </QueryClientProvider>,
  )
  const before = await screen.findByLabelText('Execução anterior'),
    after = screen.getByLabelText('Execução atual'),
    mode = screen.getByLabelText('Modo dos indicadores')
  await screen.findByRole('option', { name: /first ·/ })
  await waitFor(() => expect(before).toBeEnabled())
  await userEvent.selectOptions(before, 'first')
  await userEvent.selectOptions(after, 'later')
  await userEvent.click(screen.getByRole('button', { name: 'Comparar execuções' }))
  expect(before).toBeDisabled()
  expect(after).toBeDisabled()
  expect(mode).toBeDisabled()
  await act(async () =>
    finish({
      before_id: 'first',
      after_id: 'later',
      comparable: true,
      tests: [],
      before_scope: {},
      after_scope: {},
      scope_changes: {
        rule_versions: [],
        test_definitions: [],
        environment: [],
        rule_test_links: [],
        link_context_recorded: true,
      },
    }),
  )
  await screen.findByText('Execuções: first → later')
  await waitFor(() => expect(mode).toBeEnabled())
  expect(before).toHaveValue('first')
  expect(after).toHaveValue('later')
})
