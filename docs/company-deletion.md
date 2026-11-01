# Company deletion

Deleting a company only flags it. A Celery job purges it within about 60 seconds. Deletion starts right away and cannot be undone.

## What starts a deletion

- The dashboard calls `DELETE /api/v1/provisioning/companies/{id}`.
- A staff member deletes the company in Django admin, alone or with the bulk action. Admin never deletes the row directly.

Both set `Company.deletion_requested_at`. From then on the company:

- is hidden from every company list, including Django admin;
- gets no new tokens (sign-in, refresh, personal access tokens answer 403);
- has its refresh sessions revoked.

## The purge job

Celery beat runs `companies.purge_deleted_companies` every 60 seconds (`manage.py purge_deleted_companies` does the same run by hand). For each flagged company it:

1. Posts `/api/v1/internal/company-deletions` to each origin in `COMPANY_DELETION_SERVICE_URLS` (storage, hosting and email). The request carries an assertion signed with this server's JWT key: audience `shellui-company-deletion`, scope `company.delete`, 60 second lifetime. Services refuse it as a user token, and refuse a user token here. A service that does not answer is asked again on the next run.
2. Once every service answered, deletes the company and every row tied to it. User accounts stay.
3. Sends `identity.company.deleted` to `DASHBOARD_WEBHOOK_URL`, signed with `DASHBOARD_WEBHOOK_SECRET`, and retries it each run. An undelivered notice is dropped after 7 days. saas-service also notices the company is gone from the region list.

Each service then purges its own rows and files (S3 or disk) with its own Celery job, also every 60 seconds.

## Production

- Run a Celery worker with beat (the Docker entrypoint does) on identity, storage, hosting, email and saas.
- Set `COMPANY_DELETION_SERVICE_URLS`, `DASHBOARD_WEBHOOK_URL` and `DASHBOARD_WEBHOOK_SECRET` on each region.
