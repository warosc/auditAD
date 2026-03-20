# Docker Secrets - AD Purple Lab

Este directorio almacena secretos para usar con Docker secrets.
**NUNCA commitear archivos con contraseñas reales.**

El archivo `.gitignore` del proyecto excluye todo en este directorio excepto este README.

---

## Modo 1: Variables de entorno (por defecto)

Configurado en `.env`:

```env
AD_PASSWORD=MiPassword123
```

Usado directamente por los scripts. Simple para laboratorio local.

---

## Modo 2: Docker Secrets (recomendado para entornos compartidos)

### Paso 1: Crear archivos de secretos

```bash
echo -n "MiPasswordSegura123!" > secrets/ad_password.txt
echo -n "ChangeThisNeo4jPass123!" > secrets/neo4j_password.txt
chmod 600 secrets/*.txt
```

### Paso 2: Activar en docker-compose.yml

Descomenta el bloque `secrets:` en `docker-compose.yml`:

```yaml
secrets:
  ad_password:
    file: ./secrets/ad_password.txt
  neo4j_password:
    file: ./secrets/neo4j_password.txt
```

Y en el servicio `kali-audit`:

```yaml
secrets:
  - ad_password
environment:
  - AD_PASSWORD_FILE=/run/secrets/ad_password
```

### Paso 3: Usar en scripts

Los scripts detectan `AD_PASSWORD_FILE` automáticamente:

```bash
# kali/entrypoint.sh lee el secreto si la variable apunta a un archivo:
if [[ -f "${AD_PASSWORD_FILE:-}" ]]; then
    export AD_PASSWORD
    AD_PASSWORD=$(cat "${AD_PASSWORD_FILE}")
fi
```

---

## Comparación de modos

| Aspecto | Variables de entorno | Docker Secrets |
|---|---|---|
| Simplicidad | Alta | Media |
| Seguridad | Media | Alta |
| Visible en `docker inspect` | Sí | No |
| Adecuado para lab aislado | Sí | Opcional |
| Adecuado para CI/CD | No | Sí |

Para un laboratorio local sin acceso externo, las variables de entorno son suficientes.
