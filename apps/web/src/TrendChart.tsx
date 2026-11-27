import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { Coverage } from './types'

export default function TrendChart({ trend }: { trend: Coverage['trend'] }) {
  return (
    <div
      className="chart"
      role="img"
      aria-label={`Evolução de ${trend.length} execuções concluídas. ${trend.map((t, i) => `Execução ${i + 1}: ${t.detected} detectados de ${t.evaluated} avaliados`).join('; ')}.`}
    >
      <ResponsiveContainer width="100%" height={230}>
        <AreaChart data={trend.map((t, i) => ({ ...t, label: `#${i + 1}` }))}>
          <defs>
            <linearGradient id="detected" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--detection)" stopOpacity={0.23} />
              <stop offset="100%" stopColor="var(--detection)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 5" />
          <XAxis
            dataKey="label"
            tick={{ fill: 'var(--muted)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: 'var(--muted)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={30}
          />
          <Tooltip
            contentStyle={{
              background: 'var(--graphite)',
              border: '1px solid var(--steel)',
              borderRadius: 8,
            }}
          />
          <Area
            isAnimationActive={false}
            type="monotone"
            name="Avaliados"
            dataKey="evaluated"
            stroke="var(--frost)"
            fill="transparent"
          />
          <Area
            isAnimationActive={false}
            type="monotone"
            name="Detectados"
            dataKey="detected"
            stroke="var(--detection)"
            fill="url(#detected)"
            strokeWidth={2.5}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
