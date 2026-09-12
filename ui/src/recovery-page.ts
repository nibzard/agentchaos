// Browser entry for the recovery and governance page. The control
// plane renders the RecoveryBoard document into a JSON data island;
// this script parses it strictly and mounts the board. A malformed
// island prints the parse error as text — never a partial board.
import { parseRecovery, renderRecovery } from "./recovery";

const island = document.getElementById("recovery-data");
if (island === null) {
  throw new Error("recovery page shell is missing #recovery-data");
}
const host = document.getElementById("app");
if (host === null) {
  throw new Error("recovery page shell is missing #app");
}
try {
  const board = parseRecovery(JSON.parse(island.textContent ?? ""));
  host.innerHTML = renderRecovery(board);
} catch (error) {
  // Inert by construction: textContent cannot carry markup.
  host.textContent = error instanceof Error ? error.message : String(error);
}
