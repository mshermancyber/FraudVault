import type { IOC } from '@scanboy/shared';

// ── Types ──────────────────────────────────────────────────────────────────

export interface CSVExportOptions {
  includeHeaders: boolean;
  delimiter: string;
}

const DEFAULT_OPTIONS: CSVExportOptions = {
  includeHeaders: true,
  delimiter: ',',
};

// ── CSV Generator ──────────────────────────────────────────────────────────

/**
 * Export IOCs as a CSV string.
 */
export function exportIOCsToCSV(
  iocs: IOC[],
  submissionId: string,
  options: Partial<CSVExportOptions> = {},
): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const lines: string[] = [];

  if (opts.includeHeaders) {
    lines.push(
      joinCSVRow(
        ['submission_id', 'ioc_type', 'ioc_value', 'confidence', 'source', 'context', 'first_seen'],
        opts.delimiter,
      ),
    );
  }

  for (const ioc of iocs) {
    lines.push(
      joinCSVRow(
        [
          submissionId,
          ioc.type,
          ioc.value,
          String(ioc.confidence),
          ioc.source,
          ioc.context ?? '',
          ioc.firstSeenAt,
        ],
        opts.delimiter,
      ),
    );
  }

  return lines.join('\n') + '\n';
}

/**
 * Escape a CSV field value. Wraps in quotes if the value contains the delimiter,
 * a double-quote, or a newline.
 */
function escapeCSVField(value: string, delimiter: string): string {
  let escaped = value.replace(/"/g, '""');
  const isFormula = /^[=+\-@\t\r]/.test(escaped);
  if (isFormula) {
    escaped = "'" + escaped;
  }
  const needsQuote = isFormula || escaped.includes('"') || escaped.includes(delimiter) || escaped.includes('\n') || escaped.includes('\r');
  return needsQuote ? `"${escaped}"` : escaped;
}

function joinCSVRow(fields: string[], delimiter: string): string {
  return fields.map((f) => escapeCSVField(f, delimiter)).join(delimiter);
}
