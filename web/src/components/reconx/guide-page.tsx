export default function GuidePage() {
  return (
    <section className="max-w-3xl space-y-5">
      <h2 className="text-xl">How ReconX works</h2>
      <p>
        Start with domains you are authorized to assess. Include patterns narrow
        the scan; exclude patterns take precedence. Cloud checks require
        explicit cloud asset URLs through the CLI.
      </p>
      <ol className="list-inside list-decimal space-y-2">
        <li>Discover subdomains from passive sources and DNS.</li>
        <li>Probe scoped HTTP endpoints and discover ports.</li>
        <li>Collect URLs and inspect JavaScript.</li>
        <li>Record scanner findings and CORS candidates with evidence.</li>
        <li>Review coverage and validate security impact before reporting.</li>
      </ol>
      <p>
        Scans retain private checkpoints for retry. Failed and partial phases
        are retried on resume; a completed phase with zero results is still
        complete.
      </p>
      <p>
        The dashboard runs on localhost. Remote access requires RECONX_WEB_TOKEN
        and HTTPS. API tokens are stored in owner-only settings files.
      </p>
    </section>
  );
}
