// Browser entry for the workload overview. The page carries the
// snapshot in a JSON data island (the control plane renders it from
// its own read model); this script parses it strictly and mounts the
// inert rendering. A malformed island shows the parse error instead
// of a partial page.
import { parseOverview, renderOverview } from "./overview";

const island = document.getElementById("overview-data");
const host = document.getElementById("app");

if (island === null || host === null) {
  throw new Error("overview page shell is missing its data island");
}

let parsed: unknown;
try {
  parsed = JSON.parse(island.textContent ?? "");
} catch (error) {
  host.textContent = `overview data island is not JSON: ${error}`;
  throw error;
}

try {
  const snapshot = parseOverview(parsed);
  host.innerHTML = renderOverview(snapshot);
} catch (error) {
  // A rejected document renders as inert text, never as markup.
  host.textContent = String(error);
  throw error;
}
