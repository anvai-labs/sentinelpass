/**
 * SentinelPass Desktop UI — credential registry posture dashboard (ADR-001 P2).
 *
 * Read-only: view rotation posture, reuse clusters, and registered entities.
 * All mutation (entity creation, assignment, mark-rotated, expiry) remains a
 * CLI-only workflow for this slice — see ADR-001's migration path.
 */

import { invoke, currentEntry, noSelection, entryDetail } from './state.js';
import { showToast, escapeHtml } from './utils.js';
import { loadEntry } from './entries.js';

// ---------------------------------------------------------------------------
// Types mirroring the Rust structs (sentinelpass-core/src/registry/mod.rs,
// policy.rs). Snake_case fields verbatim to match serde output — no
// camelCase translation, consistent with how entries.ts consumes Entry.
// ---------------------------------------------------------------------------

export type RotationStatus = 'ok' | 'due_soon' | 'weak' | 'reused' | 'overdue';

export type Entity = {
    entity_id: string;
    name: string;
    kind: string;
    criticality: string;
    notes: string | null;
    rotation_interval_days_override: number | null;
    created_at: number;
    modified_at: number;
};

export type EntitySummary = {
    entity: Entity;
    credential_count: number;
};

export type ReuseCluster = {
    size: number;
    entry_ids: number[];
    titles: string[];
};

export type EntryPosture = {
    entry_id: number;
    title: string;
    entity_name: string | null;
    status: RotationStatus;
    reasons: string[];
    resolved_interval_days: number;
    days_since_rotation: number | null;
    reuse_count: number;
    strength_score: number | null;
    tool_managed: boolean;
    expires_at: number | null;
};

export type RegistryOverview = {
    entities: EntitySummary[];
    reuse_clusters: ReuseCluster[];
    posture: EntryPosture[];
    unassigned_entries: number;
};

// ---------------------------------------------------------------------------
// Module state (local — nothing else needs registry data)
// ---------------------------------------------------------------------------

let overview: RegistryOverview | null = null;

const STATUS_LABELS: Record<RotationStatus, string> = {
    ok: 'OK',
    due_soon: 'DUE',
    weak: 'WEAK',
    reused: 'REUSED',
    overdue: 'OVERDUE',
};

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

/**
 * Fetch a cheap (no-decrypt) registry overview on unlock, purely to
 * populate the header badge count. Safe to call even if the registry
 * index hasn't been built yet — the backend sweeps it lazily on demand.
 */
export async function loadRegistryBadgeCount() {
    try {
        const result: RegistryOverview = await invoke('get_registry_overview', {
            includeStrength: false,
        });
        updateRegistryBadge(result.posture.length);
    } catch (error) {
        // Best-effort — a badge-count failure shouldn't surface an error
        // toast on every unlock; the dashboard itself will report errors
        // when actually opened.
        console.warn('Failed to load registry badge count:', error);
    }
}

function updateRegistryBadge(count: number) {
    const badge = document.getElementById('registry-badge');
    if (!badge) {
        return;
    }
    if (count > 0) {
        badge.textContent = String(count);
        badge.classList.remove('hidden');
    } else {
        badge.classList.add('hidden');
    }
}

/**
 * Fetch the full (strength-inclusive) registry overview and render the
 * dashboard. Shows a loading state while in flight — this may include a
 * bounded full-vault decrypt sweep on first open after upgrade.
 */
export async function loadRegistryOverview() {
    const loading = document.getElementById('registry-loading');
    loading?.classList.remove('hidden');
    try {
        overview = await invoke('get_registry_overview', { includeStrength: true });
        renderRegistryDashboard(overview);
        updateRegistryBadge(overview.posture.length);
    } catch (error) {
        showToast(error, 'error');
    } finally {
        loading?.classList.add('hidden');
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderRegistryDashboard(data: RegistryOverview) {
    const onboardingBanner = document.getElementById('registry-onboarding-banner');
    if (onboardingBanner) {
        onboardingBanner.classList.toggle('hidden', data.entities.length > 0);
    }

    renderStatusStrip(data.posture);
    renderFindingsList(data.posture);
    renderEntitiesList(data.entities);
}

function renderStatusStrip(posture: EntryPosture[]) {
    const headline = document.getElementById('registry-status-headline');
    if (!headline) {
        return;
    }
    const findingCount = posture.length;
    headline.textContent =
        findingCount === 0
            ? 'All clear'
            : `${findingCount} ${findingCount === 1 ? 'finding needs' : 'findings need'} attention`;
}

function renderFindingsList(posture: EntryPosture[]) {
    const container = document.getElementById('registry-findings');
    if (!container) {
        return;
    }

    if (posture.length === 0) {
        container.innerHTML = '<div class="registry-list-empty">No rotation findings — everything looks OK.</div>';
        return;
    }

    container.innerHTML = posture
        .map(
            (entry) => `
        <div class="registry-finding-row" data-entry-id="${entry.entry_id}">
            <div class="registry-finding-row-header" data-action="open-entry">
                <div class="registry-finding-title">${escapeHtml(entry.title)}${
                entry.entity_name
                    ? ` <span class="metadata-muted">&middot; ${escapeHtml(entry.entity_name)}</span>`
                    : ''
            }</div>
                <span class="status-badge status-${entry.status.replace(/_/g, '-')}">${
                STATUS_LABELS[entry.status]
            }</span>
            </div>
            <div class="registry-finding-reasons">
                interval=${entry.resolved_interval_days}d
                ${entry.days_since_rotation !== null ? ` age=${entry.days_since_rotation}d` : ''}
                ${entry.tool_managed ? ' &middot; tool-managed' : ''}
                ${entry.reasons.map((reason) => `<br>&bull; ${escapeHtml(reason)}`).join('')}
            </div>
            ${
                entry.status === 'reused'
                    ? `<button class="registry-disclosure-toggle" data-action="toggle-cluster" data-entry-id="${entry.entry_id}">shared with ${
                          entry.reuse_count - 1
                      } other${entry.reuse_count - 1 === 1 ? '' : 's'} &rarr;</button>
                       <div class="registry-cluster-members hidden" data-cluster-for="${entry.entry_id}"></div>`
                    : ''
            }
        </div>
    `
        )
        .join('');

    container.querySelectorAll('[data-action="open-entry"]').forEach((el) => {
        el.addEventListener('click', () => {
            const entryId = parseInt((el.closest('.registry-finding-row') as HTMLElement).dataset.entryId!);
            openEntityFromPosture(entryId);
        });
    });

    container.querySelectorAll('[data-action="toggle-cluster"]').forEach((el) => {
        el.addEventListener('click', (event) => {
            event.stopPropagation();
            const entryId = parseInt((el as HTMLElement).dataset.entryId!);
            toggleReuseDisclosure(entryId);
        });
    });
}

function toggleReuseDisclosure(entryId: number) {
    if (!overview) {
        return;
    }
    const membersContainer = document.querySelector(
        `[data-cluster-for="${entryId}"]`
    ) as HTMLElement | null;
    if (!membersContainer) {
        return;
    }

    if (!membersContainer.classList.contains('hidden')) {
        membersContainer.classList.add('hidden');
        return;
    }

    const cluster = overview.reuse_clusters.find((c) => c.entry_ids.includes(entryId));
    if (!cluster) {
        return;
    }
    const otherTitles = cluster.entry_ids
        .map((id, i) => ({ id, title: cluster.titles[i] }))
        .filter((member) => member.id !== entryId && member.title !== undefined)
        .map((member) => escapeHtml(member.title));
    membersContainer.textContent = otherTitles.length > 0 ? `Also used by: ${otherTitles.join(', ')}` : 'Also used by another entry.';
    membersContainer.classList.remove('hidden');
}

async function openEntityFromPosture(entryId: number) {
    await loadEntry(entryId);
    document.getElementById('registry-dashboard')?.classList.add('hidden');
}

function renderEntitiesList(entities: EntitySummary[]) {
    const container = document.getElementById('registry-entities');
    if (!container) {
        return;
    }

    if (entities.length === 0) {
        container.innerHTML = '';
        return;
    }

    container.innerHTML = entities
        .map(
            (summary) => `
        <div class="registry-entity-row">
            <div class="registry-entity-row-header">
                <div class="registry-finding-title">${escapeHtml(summary.entity.name)}</div>
                <span class="entry-type-pill">${escapeHtml(summary.entity.kind)}</span>
            </div>
            <div class="registry-finding-reasons">
                criticality=${escapeHtml(summary.entity.criticality)} &middot; ${summary.credential_count} credential${
                summary.credential_count === 1 ? '' : 's'
            }
            </div>
        </div>
    `
        )
        .join('');
}

// ---------------------------------------------------------------------------
// Panel visibility
// ---------------------------------------------------------------------------

export function showRegistryDashboard() {
    noSelection?.classList.add('hidden');
    entryDetail?.classList.add('hidden');
    document.getElementById('registry-dashboard')?.classList.remove('hidden');
    void loadRegistryOverview();
}

export function hideRegistryDashboard() {
    document.getElementById('registry-dashboard')?.classList.add('hidden');
    if (currentEntry) {
        entryDetail?.classList.remove('hidden');
    } else {
        noSelection?.classList.remove('hidden');
    }
}
