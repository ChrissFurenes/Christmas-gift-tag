# Christmas Gift Tag (Go)

En webapp for julegaveetiketter. Opprett gave med hemmelig melding, mottaker/avsender og åpningstid. Last ned unik QR-kode, registrer tidlige besøk, og åpne gaven manuelt fra admin.

## Kjør med Docker

```sh
cp .env.example .env
# Endre ADMIN_PASSWORD (minst 12 tegn) og BASE_URL i .env
docker compose up --build -d
```

Åpne http://localhost:8080/admin. QR-kodene bruker `BASE_URL` slik at lenken må være tilgjengelig for mottakeren.

## Kjør lokalt

```sh
cp .env.example .env
# Sett miljøvariabler fra .env, f.eks. med `set -a; source .env; set +a`
go mod tidy
go run .
```

## Viktig før offentlig utrulling

Dette er en prototype for én administrator. Administratorøkten er lagret i minnet og blir ugyldig ved omstart. Det finnes ikke CSRF-beskyttelse, rate limiting, brukeradministrasjon eller sikkerhetsrevisjon. Legg appen bak HTTPS, og implementer CSRF-token, sikker sesjonshåndtering, bruteforce-beskyttelse og tilgangsstyring før produksjon. QR-lenken er en hemmelig, tilfeldig ID: alle som har den kan se gaveinnholdet etter åpning. "Peeks" teller sidevisninger før åpning, ikke unike personer.
