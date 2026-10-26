import type { Flow } from '../api/types'
import { bytes, dateTime, num, portLabel } from '../lib/format'
import { Country, Ip, ShowMore } from './ui'
import { useShown } from '../lib/useShown'

export function FlowTable({ flows, first = 15 }: { flows: Flow[]; first?: number }) {
  const list = useShown(flows, first, 25)
  return (
    <>
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
          {list.shown.map((f, i) => (
            <tr key={f.id} className={list.fresh(i) ? 'row-in' : undefined}>
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
    <ShowMore remaining={list.remaining} next={list.next} onClick={list.showMore} noun="flows" />
    </>
  )
}
