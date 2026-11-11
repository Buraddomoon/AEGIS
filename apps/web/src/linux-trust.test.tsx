import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { LinuxTrust } from './LinuxTrust'
import type { Lab } from './types'

const lab = {
  environment_version: 3,
  trust: {
    configuration_hash: 'a'.repeat(64),
    deployment_configuration_hash: 'a'.repeat(64),
    matches_deployment: true,
    reviewed_by: 'reviewer',
    reviewed_at: '2026-11-11T15:00:00Z',
  },
} as Lab
afterEach(cleanup)

it('shows the reviewed trust, current environment and separate authorization requirement', () => {
  render(<LinuxTrust lab={lab} />)
  expect(screen.getByText('Vínculo corresponde à confiança atual')).toBeInTheDocument()
  expect(screen.getByText(/ambiente v3/)).toBeInTheDocument()
  expect(screen.getByText(/autorização do laboratório/)).toBeInTheDocument()
})

it('hides a positive status after trust changes even if a cached flag claims a match', () => {
  const view = render(<LinuxTrust lab={lab} />)
  view.rerender(
    <LinuxTrust
      lab={{ ...lab, trust: { ...lab.trust!, deployment_configuration_hash: 'b'.repeat(64) } }}
    />,
  )
  expect(screen.queryByText('Vínculo corresponde à confiança atual')).not.toBeInTheDocument()
  expect(screen.getByText('Confiança exige revisão do vínculo')).toBeInTheDocument()
})

it('requires review when no valid fingerprint is supplied', () => {
  render(<LinuxTrust lab={{ ...lab, trust: null }} />)
  expect(screen.getByText('Confiança exige revisão do vínculo')).toBeInTheDocument()
})
