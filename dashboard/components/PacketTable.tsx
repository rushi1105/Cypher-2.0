"use client";

import { useMemo } from "react";
import type { PacketEvent } from "@/lib/types";
import { formatBytes, formatTime } from "@/lib/format";

export function PacketTable({
  packets,
  filter,
  setFilter,
  protocol,
  setProtocol,
  blockedOnly,
  setBlockedOnly,
}: {
  packets: PacketEvent[];
  filter: string;
  setFilter: (value: string) => void;
  protocol: string;
  setProtocol: (value: string) => void;
  blockedOnly: boolean;
  setBlockedOnly: (value: boolean) => void;
}) {
  const protocols = useMemo(
    () => ["All", ...Array.from(new Set(packets.map((packet) => packet.proto))).sort()],
    [packets],
  );

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return packets.filter((packet) => {
      if (protocol !== "All" && packet.proto !== protocol) return false;
      if (blockedOnly && !packet.blocked) return false;
      if (!needle) return true;
      return [packet.src, packet.dst, packet.app, packet.sni, packet.proto]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [packets, filter, protocol, blockedOnly]);

  return (
    <div className="card table-card">
      <div className="table-header">
        <div>
          <div className="card-title">Packet stream</div>
          <div className="muted">{visible.length} visible / {packets.length} captured</div>
        </div>
        <div className="table-controls">
          <input
            className="input"
            placeholder="Filter IP, app, SNI..."
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
          <select className="input" value={protocol} onChange={(event) => setProtocol(event.target.value)}>
            {protocols.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <label className="toggle">
            <input
              type="checkbox"
              checked={blockedOnly}
              onChange={(event) => setBlockedOnly(event.target.checked)}
            />
            Blocked only
          </label>
        </div>
      </div>

      <div className="table-wrap">
        <table className="packet-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Proto</th>
              <th>App</th>
              <th>SNI / Host</th>
              <th>Dir</th>
              <th>Size</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {visible.slice(0, 250).map((packet, index) => (
              <tr
                key={`${packet.flow_id}-${packet.ts}-${index}`}
                className={packet.blocked ? "row-blocked" : undefined}
              >
                <td className="mono">{formatTime(packet.ts)}</td>
                <td className="mono">{packet.src}:{packet.sport}</td>
                <td className="mono">{packet.dst}:{packet.dport}</td>
                <td><span className={`pill pill-${packet.proto.toLowerCase()}`}>{packet.proto}</span></td>
                <td>{packet.app}</td>
                <td className="mono muted">{packet.sni || "-"}</td>
                <td><span className="pill">{packet.direction}</span></td>
                <td className="mono">{formatBytes(packet.size)}</td>
                <td>
                  <span className={packet.blocked ? "pill pill-blocked" : "pill pill-forwarded"}>
                    {packet.blocked ? "blocked" : "forwarded"}
                  </span>
                </td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={9} className="empty-row">No packets yet. Start a replay.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
