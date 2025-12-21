# Docker Build Rules - MANDATORY

## Frontend Build Rules

### ✅ MUST DO

1. **Vite output directory**: Always use `outDir: 'build'` in `vite.config.ts`
2. **Dockerfile build command**: Always include `--outDir build` flag: `npx vite build --outDir build`
3. **Dockerfile COPY**: Always copy from `/app/build/` not `/app/dist/`
4. **Node version**: Use `node:20-alpine` as base image
5. **Nginx version**: Use `nginx:alpine` for production

### ❌ NEVER DO

- Do not change output directory without updating Dockerfile
- Do not use dist instead of build
- Do not add complex shell scripts to RUN commands
- Do not assume default Vite behavior (always be explicit)

## Backend Build Rules

### ✅ MUST DO

1. **CMD shell**: Always use `/bin/sh` not `sh`: `CMD ["/bin/sh", "-c", "..."]`
2. **Healthcheck**: Use curl with full path: `CMD curl -f http://localhost:8080/api/v1/health || exit 1`
3. **Python version**: Use `python:3.12-slim` as base image
4. **Multi-stage build**: Always use builder pattern to minimize image size

### ❌ NEVER DO

- Do not use `sh` without full path `/bin/sh`
- Do not use wget for healthchecks (use curl)
- Do not change healthcheck endpoints without verifying backend routes

## Docker Compose Rules

### ✅ MUST DO

1. **Healthchecks**: Always define healthchecks in docker-compose.yml (overrides Dockerfile)
2. **Dependencies**: Use `depends_on` with `condition: service_healthy`
3. **Networks**: Always use custom networks, never default bridge
4. **Restart policy**: Use `unless-stopped` for services

### ❌ NEVER DO

- Do not run builds without `--no-cache` when testing fixes
- Do not deploy without verifying healthchecks pass
- Do not remove existing healthchecks

## Testing Before Deploy

```bash
# ALWAYS run these before considering build successful:
1. docker compose build SERVICE --no-cache
2. docker compose up -d SERVICE
3. docker inspect SERVICE | grep -A 10 "Health"
4. Wait 60 seconds and verify Status: "healthy"
```

## Recovery Commands

If build fails:

```bash
# Frontend
docker compose down frontend
docker compose build frontend --no-cache 2>&1 | tee frontend-build.log
# Check frontend-build.log for errors

# Backend
docker compose down backend
docker compose build backend --no-cache 2>&1 | tee backend-build.log
# Check backend-build.log for errors
```

## Critical Files

These files control the build process - changes must be tested:

- `frontend/Dockerfile` - Frontend image build
- `frontend/vite.config.ts` - Vite build configuration
- `src/Dockerfile` - Backend image build
- `docker-compose.yml` - Service orchestration
- `.dockerignore` - Files excluded from build context

## Approval Required

Changes to these files REQUIRE explicit user approval:

- Any Dockerfile
- docker-compose.yml
- vite.config.ts
- package.json (if affects build)
- requirements.txt (if affects build)
