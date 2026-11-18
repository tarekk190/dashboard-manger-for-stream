// Normalized data models for PX League
// These are plain JavaScript objects that represent the data we expose via the Worker.
// Actual field names are kept generic because the upstream YSScores schema is not yet verified.

/**
 * Match model
 * @typedef {Object} Match
 * @property {string} id            - Unique match identifier (as provided by YSScores).
 * @property {Team} homeTeam       - Home team information.
 * @property {Team} awayTeam       - Away team information.
 * @property {string} league        - Competition / league name.
 * @property {Score} score         - Current or final score.
 * @property {string} status        - Human‑readable status (e.g., "live", "ended", "upcoming").
 * @property {string} startTime    - ISO‑8601 timestamp of kickoff (if available).
 */

/**
 * Team model
 * @typedef {Object} Team
 * @property {string} id   - Team identifier.
 * @property {string} name - Team name (Arabic).
 * @property {string} logo - URL to a logo image (may be placeholder).
 */

/**
 * Score model
 * @typedef {Object} Score
 * @property {number} home - Home team goals.
 * @property {number} away - Away team goals.
 */

/**
 * Event model (e.g., goal, card)
 * @typedef {Object} Event
 * @property {string} type      - Event type (e.g., "goal", "yellow_card").
 * @property {string} minute    - Minute of the event.
 * @property {Team} team        - Team associated with the event.
 * @property {string} player    - Player name (if available).
 */

/**
 * Lineup model – list of players for a side
 * @typedef {Object} Lineup
 * @property {Team} team           - Team the lineup belongs to.
 * @property {Array<string>} players - Array of player names (Arabic) in order.
 */

module.exports = {
  // Exporting as constructor‑less plain objects; real mapping will be performed in adapter.js
};
