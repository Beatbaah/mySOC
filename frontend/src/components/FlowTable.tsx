import type { Flow } from '../api/types'
import { bytes, dateTime, num, portLabel } from '../lib/format'
import { Country, Ip } from './ui'

export function FlowTable({ flows }: { flows: Flow[] }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Start</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Proto</th>
            <th className="num">Packets</th>
            <th className="num">Bytes</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((f) => (
            <tr key={f.id}>
              <td className="muted nowrap">{dateTime(f.start)}</td>
              <td className="nowrap"><Ip ip={f.srcIp} /><span className="faint mono" style={{ fontSize: 11 }}>:{f.srcPort}</span> {f.srcCountry && <span className="faint" style={{ fontSize: 12 }}><Country code={f.srcCountry} /></span>}</td>
              <td className="nowrap"><Ip ip={f.dstIp} /><span className="faint mono" style={{ fontSize: 11 }}>:{portLabel(f.dstPort)}</span> {f.dstCountry && <span className="faint" style={{ fontSize: 12 }}><Country code={f.dstCountry} /></span>}</td>
              <td>{f.protocol}</td>
              <td className="num">{num(f.packets)}</td>
              <td className="num">{bytes(f.bytes)}</td>
              <td className="mono faint" style={{ fontSize: 11 }}>{f.tcpFlags}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
