// Browser entry for the comparison and assurance page. The control
// plane renders a ProfileComparison document and an array of
// AssuranceClaim cards into JSON data islands; this script parses
// both strictly and mounts the frontier and the cards. A malformed
// island prints the parse error as text — never a partial view.
import {
  parseClaimCard,
  parseComparison,
  renderClaimCard,
  renderComparison,
} from "./compare";

function readIsland(id: string): unknown {
  const island = document.getElementById(id);
  if (island === null) {
    throw new Error(`comparison page shell is missing #${id}`);
  }
  return JSON.parse(island.textContent ?? "");
}

const host = document.getElementById("app");
if (host === null) {
  throw new Error("comparison page shell is missing #app");
}

try {
  const comparison = parseComparison(readIsland("comparison-data"));
  const rawClaims = readIsland("claims-data");
  if (!Array.isArray(rawClaims)) {
    throw new Error("comparison document: $.claims: expected an array");
  }
  const claims = rawClaims.map((raw, index) => {
    try {
      return parseClaimCard(raw);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`claim ${index}: ${error.message}`);
      }
      throw error;
    }
  });
  const cards = claims.length === 0
    ? `<section class="claims"><h2>Assurance claims</h2>` +
      `<p class="empty">none</p></section>`
    : `<section class="claims"><h2>Assurance claims</h2>` +
      `<p>each card is its own scoped conclusion; the page never ` +
      `combines them into one safety score</p>` +
      claims.map(renderClaimCard).join("") + `</section>`;
  host.innerHTML = renderComparison(comparison) + cards;
} catch (error) {
  // Inert by construction: textContent cannot carry markup.
  host.textContent = error instanceof Error ? error.message : String(error);
}
