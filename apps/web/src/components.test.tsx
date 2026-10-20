import { render, screen, waitFor, cleanup } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import { Badge } from './lib'
import { Catalog } from './Catalog'

afterEach(()=>{cleanup();vi.restoreAllMocks()})
const techniques=[{id:'T1059.004',name:'Unix Shell',description:'Official fixture metadata',tactics:['execution'],platforms:['Linux'],parent_id:'T1059',reference:'https://attack.mitre.org/techniques/T1059/004/',dataset_version:'20.0',coverage:'NOT_TESTED'}]
function renderCatalog(){return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><Catalog/></QueryClientProvider>)}
describe('Coverage and catalog states',()=>{
  it('labels observed events without claiming detection',()=>{render(<Badge value="OBSERVED_NOT_ALERTED"/>);expect(screen.getByText('Observado sem alerta')).toBeInTheDocument();expect(screen.queryByText('Detectado')).not.toBeInTheDocument()})
  it('filters techniques and shows an explicit empty result',async()=>{
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:true,status:200,json:async()=>({items:techniques,total:1})}))
    renderCatalog();await screen.findByText(/Unix Shell/)
    await userEvent.type(screen.getByLabelText('Pesquisar técnica'),'nonexistent')
    expect(screen.getByText('Nenhuma técnica corresponde aos filtros')).toBeInTheDocument()
    await userEvent.clear(screen.getByLabelText('Pesquisar técnica'))
    await userEvent.selectOptions(screen.getByLabelText('Filtrar por cobertura'),'DETECTED')
    expect(screen.queryByText(/Unix Shell/)).not.toBeInTheDocument()
    expect(screen.getByText('Nenhuma técnica corresponde aos filtros')).toBeInTheDocument()
  })
  it('shows API errors instead of fabricated catalog values',async()=>{
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:false,status:503,json:async()=>({error:{message:'Banco indisponível'}})}))
    renderCatalog()
    await waitFor(()=>expect(screen.getByRole('alert')).toHaveTextContent('Banco indisponível'),{timeout:4000})
    expect(screen.queryByText(/Unix Shell/)).not.toBeInTheDocument()
  })
})
