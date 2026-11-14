# Christmas Gift Tag – Go v4.4 (utskrift)

Selvhostet webapp som lager QR-etiketter til julegaver, med private brukerkontoer og valgfri passord-/datolås. Hver etikett får sin egen lange tilfeldige URL. Til/fra og valgfri hemmelig melding er **skjult for den offentlige gavesiden frem til åpning**.


## Nytt i v4.4 – velg og skriv ut QR-etiketter

På **Mine etiketter** finner du nå avkrysningsbokser for hver etikett, og en utskriftsmeny over listen:

1. Merk de etikettene du vil skrive ut (eller bruk **Velg alle viste**; fungerer også etter søk).
2. Klikk **Skriv ut valgte**. Et nytt vindu åpnes med utskriftsvisning og nettleserens utskriftsdialog.
3. Standardoppsettet er A4 med **seks QR-etiketter per ark**, hver merket med nummer og kort referanse.
4. Etter QR-arkene får du et **eget oversiktsark** som viser referansen, mottaker og avsender, slik at du vet hvilken kode som hører til hvilken pakke.
5. Hvis du ønsker **Til/Fra på selve QR-etiketten**, huk av for det før utskrift. Du kan også velge å vise private notater på oversiktsarket (av som standard).

For enkel utskrift er antallet begrenset til **60 etiketter per utskriftsjobb**. Ingen gavepassord eller hemmelige meldinger er med i utskriften. Vær oppmerksom på at oversiktsarket inneholder private navn; oppbevar det separat fra gavene.

**Eierbegrensning på serversiden:** Utskrift krever innlogging og CSRF-token. Hver valgte etikett kontrolleres i databasen med `owner_id` lik den innloggede brukeren. Hvis én ID ikke tilhører denne brukeren, avvises **hele** utskriften. **Administrator har ikke unntak** fra regelen. Også nedlasting av QR-bilder (`/admin/gifts/{id}/qr.png`) krever at man er eieren. Den gamle offentlige QR-bildeadressen er fjernet; **selve QR-lenken til `/gift/{id}` fortsetter å fungere** som før.

**Oppdatering:** Behold `.env` og Docker-volumet. Erstatt prosjektfilene og kjør `docker compose up --build -d`. Ingen nye miljøvariabler eller migreringer kreves.

## Nytt i v4.3

- På ny etikett settes **24. desember inneværende år kl. 17:00 (Europe/Oslo)** automatisk. «Fjern dato» gjør feltet tomt; «24. desember» legger datoen tilbake. Eksisterende etiketter uten dato får **ikke** ny dato bare fordi du redigerer dem.
- Når dato er satt kan eieren krysse av separat for **«Tillat gavepassord før åpningsdato»** og **«Krev gavepassord også etter åpningsdato»**. Avhukingene fungerer som tidligere, men teksten er tydeligere. Begge krever at gavepassordet faktisk er satt.
- **Avsender** på nye etiketter forhåndsutfylles med brukerens visningsnavn. Du kan endre navnet under «Endre avsendernavn» på dashbordet. Gamle brukerkontoer får brukernavnet som startverdi; du kan skrive et annet navn. Valg av avsender kan fortsatt redigeres per etikett.
- **Søkefelt** filtrerer egne etiketter direkte mens du skriver. Det søker i mottaker, avsender og privat notat (og etikett-ID), uten å hente frem andre brukeres etiketter.
- Dashboardet viser tydelig **🔐 Gavepassord er satt / 🔓 Intet gavepassord**. En **«Vis gavepassord»**-knapp henter passordet kun når eieren ber om det, og lar eieren skjule det igjen. Hemmeligheten finnes ikke i HTML-kilden til dashbordet.
- **Lokal egenregistrering** kan overstyres i `.env` gjennom `LOCAL_SIGNUP_ENABLED=true` eller `false`. Hvis verdien er tom, brukes administratorens eksisterende bryter i webgrensesnittet. Ved eksplisitt env-innstilling blir UI-bryteren skrivebeskyttet.

### Viktig om lagring og synliggjøring av gavepassord

Før v4.3 ble gavepassord kun lagret som en **énveis passordhash**. Det er umulig å vise disse gamle passordene direkte. For å vise passord til en eksisterende etikett må eieren først redigere etiketten og sette et **nytt gavepassord**.

Nye passord lagres både som en PBKDF2-hash (for verifisering) og kryptert med AES-256-GCM (for eierens «Vis»-funksjon). Sett en sterk, **permanent** `GIFT_PASSWORD_KEY` i `.env` før nye passord opprettes. Byttes nøkkelen, vil tidligere krypterte passord ikke lenger kunne vises; mottaker kan fortsatt låse opp med passordet fordi verifiseringshashen lagres separat. Hvis `GIFT_PASSWORD_KEY` ikke settes, brukes `TICKET_SECRET`, deretter `ADMIN_PASSWORD`, som reserve. Dette gjør oppgradering mulig uten ny nøkkel, men en dedikert nøkkel anbefales. Ta backup av `.env` og database på en sikker måte.

En administrator med tilgang til filsystem eller serverens miljøhemmeligheter kan dekryptere gavepassord. Innlogget admin uten tilgang til andre brukeres kontoer får fortsatt ikke se deres gavepassord i applikasjonens UI/API.

### Oppdater eksisterende installasjon

Ta først sikkerhetskopi av Docker-volumet (SQLite-data) og eksisterende `.env`. Behold samme Compose-prosjektnavn og volum, oppdater kildefilene, legg til de valgfrie miljøvariablene nedenfor og kjør:

```bash
docker compose up --build -d
```

**Innstillinger i `.env`:**

```dotenv
# Valgfritt: tom = administreres via webgrensesnitt, true = på, false = av
LOCAL_SIGNUP_ENABLED=false
# Anbefales: lang og tilfeldig; endre aldri etter at nye gavepassord er opprettet
GIFT_PASSWORD_KEY=BYTT-TIL-EN-LANG-TILFELDIG-HEMMELIGHET
```

Automatisk migrering legger til feltene `users.display_name` og `gifts.password_ciphertext`. Ingen etiketter slettes. Ved feil i bygging, se `docker compose logs --tail=100 christmas-gift-tag`.

## Funksjoner

- Flere brukere, hver med egne etiketter, redigering, QR-koder og privat oversikt. Administrator kan tillate lokal egenregistrering (avslått som standard, kan også settes i `.env`).
- **Administrator kan opprette, deaktivere, aktivere og slette brukere.** Administrator kan ikke se andres etiketter (bare **antall** per bruker for å varsle ved sletting). Administrator kan fortsatt lage egne etiketter.
- En bruker som skal slettes må bekreftes på egen side. Hvis brukeren har etiketter, vises antallet i en tydelig advarsel; kontoen **og alle etikettene slettes permanent**. Bekreftelsen avvises om etikettantallet har endret seg.
- Valgfri åpningsdato (nye etiketter forhåndsutfylles med 24. desember), hemmelig melding og gavepassord.
- Når dato er valgt: **Krev passord etter tidspunktet** og **Tillat åpning med passord før tidspunktet** kan velges uavhengig.
- **Privat beskrivelse / notat** er skjult bak en «Vis»-knapp i oversikt og skjema. Notatet sendes aldri til den offentlige gavesiden.
- Forhåndsvisning av nye/endrede felt før lagring samt av hver lagret etikett. Eksisterende etiketter kan vises som åpne eller låste uten å øke besøkstelleren.
- GitHub OAuth, en generisk OpenID Connect-leverandør (f.eks. Authentik, Keycloak, Google eller Microsoft Entra ID) og LDAP/AD. Admin styrer **av/på** for hver i «Brukere og innlogging». Identitetene lagres per leverandør-ID, og knyttes ikke til lokale kontoer basert på navn eller e-post.
- Sikkerhetskontroller: hashed passord, persistent sesjonslagring, CSRF-token per sesjon, HTTPS-flagg på cookies, OAuth state + PKCE + OIDC nonce og tokenvalidering, LDAP over TLS, rate limiting i minnet.

## Åpningsregler

| Åpningsdato | Gavepassord | Krev etter dato | Tillat før dato | Oppførsel |
| --- | --- | --- | --- | --- |
| Nei | Nei | – | – | Manuell åpning av eier |
| Nei | Ja | – | – | Passord åpner når som helst |
| Ja | Nei | – | – | Åpnes automatisk på dato |
| Ja | Ja | Ja | Nei | Låst til dato, deretter passord |
| Ja | Ja | Nei | Nei | Låst til dato, deretter direkte tilgang |
| Ja | Ja | Ja | Ja | Passord før og etter dato |
| Ja | Ja | Nei | Ja | Passord før dato, åpen uten passord etter dato |

Eieren kan overstyre åpningsdatoen med «Åpne manuelt». Hvis passord kreves etter dato, kreves det også ved manuell overstyring. Er det ingen dato, men gavepassord, kreves passord også ved manuell åpning.

## Fikset i v4.1 – «Ugyldig opprinnelse» ved innlogging

Tidligere måtte HTTP `Origin` være identisk med `BASE_URL`, slik at lokal innlogging
kunne feile dersom den publiserte adressen var forskjellig fra `localhost` eller
`127.0.0.1`. Nå sammenlignes `Origin` med `Host` på forespørselen, samt
forventet HTTP/HTTPS-skjema. `BASE_URL` brukes fortsatt som kanonisk adresse
for QR-lenker og OAuth-callbacks og som HTTPS-indikator ved terminering på en
reverse proxy med samme hostnavn. Andre opprinnelser avvises fortsatt.

Etter oppdatering, kjør `docker compose up --build -d`. Behold samme Compose-prosjektnavn
og volum for å beholde etiketter og konti. Administratorpassordet endres ikke ved
oppgradering.

## Start

```bash
cp .env.example .env
# Endre ADMIN_PASSWORD, TICKET_SECRET og BASE_URL i .env
docker compose up --build -d
```

Åpne `http://localhost:8080/login`. Ved **første oppstart** opprettes kontoen `admin` med passordet fra `ADMIN_PASSWORD`. Deretter kan administrator opprette lokale brukere via `/admin/users`.

**Viktig om oppdatering fra v1/v2/v3:** Ta backup av SQLite-volumet før oppdatering. Behold eksisterende Compose-prosjektnavn/volum, og kjør `docker compose up --build -d` fra samme prosjektmappe. Migrering skjer automatisk: alle gamle etiketter får administrator som eier. Endring i `ADMIN_PASSWORD` etter første oppstart endrer ikke den eksisterende admin-kontoen; admin endrer sitt passord fra sin egen etikettside etter innlogging. Eldre sesjonscookies blir ugyldige. En migrert gave med både dato og passord beholder standardregelen om passord etter dato og ingen forhåndsåpning.

Go 1.23+ kreves. Kjør `go mod tidy && go test ./...` og `go run .` for lokal utvikling. Dependencies lastes første gang (internett påkrevd). Ikke legg `.env` i versjonskontroll.

## Ekstern pålogging

Lokal egenregistrering og alle eksterne leverandører er **avslått som standard**, også når miljøvariabler er satt. Gå til **Brukere og innlogging** som admin og aktiver ønsket leverandør.

### GitHub

1. Opprett en **GitHub OAuth App** under GitHub Developer Settings.
2. Bruk callback: `https://DITT-DOMENE/auth/github/callback` (erstatt med din BASE_URL).
3. Fyll `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` i `.env`; start containeren på nytt.
4. Administrator huker av **GitHub OAuth** og lagrer.

GitHub-brukerens stabile numeriske ID brukes som identitet. Ved første innlogging opprettes en vanlig brukerkonto. GitHub OAuth inneholder `state` og PKCE. Ingen administratorrettigheter tildeles av eksterne leverandører.

### OpenID Connect (andre tjenester)

Bruk for eksempel Authentik, Keycloak, Google Workspace eller Microsoft Entra ID. Sett issuer-URL, client ID og secret i `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`. Registrer redirect URI `https://DITT-DOMENE/auth/oidc/callback`, og slå på i administrasjonen. Serveren bruker leverandørens discovery endpoint og verifiserer signatur, issuer, audience, expiry og nonce på ID-token via `go-oidc`.

### LDAP / Active Directory

Sett for eksempel:

```dotenv
LDAP_URL=ldaps://ad.example.org:636
LDAP_BASE_DN=dc=example,dc=org
LDAP_USER_FILTER=(sAMAccountName=%s)
LDAP_BIND_DN=cn=readonly,ou=service,dc=example,dc=org
LDAP_BIND_PASSWORD=your-ldap-service-password
```

For OpenLDAP kan du bruke `(uid=%s)`. Kun `ldaps://` eller `ldap://` **med StartTLS** er tillatt. TLS-sertifikater må valideres. Administrator må aktivere LDAP i UI. Brukerne logger inn gjennom det vanlige brukernavn-/passordskjemaet; en lokal konto opprettes ved første vellykkede kataloginnlogging, men er separat fra eventuelle lokale kontoer med samme navn. Eksterne identiteter kan deaktiveres av administrator i appen.

## Personvern og begrensninger

- Eierbegrensning håndheves i databaseoppslag for etikettsider i dashbord, redigering, forhåndsvisning, åpning og sletting. Offentlig gaveside kan selvsagt åpnes av alle med QR-lenken **når gavens regler tillater det**.
- Administrator kan se **antall** etiketter og administrere kontoen, men får ingen liste over andres etiketter. Administrator med direkte server-/databaseadgang kan teknisk lese databasens innhold: dette er ikke kryptografisk ende-til-ende-isolasjon.
- Privat notat er bare skjult i eierens grensesnitt, **ikke kryptert i databasen**. Det finnes i HTML-kilden på eierens dashboard selv når notatet er skjult på skjermen. Det vises aldri på offentlig gave-URL.
- Førstegangsinnlogging hos GitHub/OIDC/LDAP oppretter brukerkontoer automatisk *hvis administrator har aktivert leverandøren*. Lokal egenregistrering er også tilgjengelig om administrator aktiverer dette under «Brukere og innlogging»; standard er avslått.
- Ekstern innlogging bør bare aktiveres over **HTTPS**, og miljøhemmeligheter må oppbevares forsvarlig. Siden er en fungerende prosjektimplementasjon, **ikke en uavhengig sikkerhetsrevidert produksjonstjeneste**. Legg gjerne rate limiting og tilgangslogger på en reverse proxy.
- Lokale brukere endrer sine egne passord. Administrator kan **ikke** tilbakestille passord via grensesnittet. For faktisk kryptografisk isolasjon fra server-/databaseadministrator må data krypteres ende-til-ende med nøkler administrator ikke har tilgang til.
- Ingen eksterne identitetsleverandører er direkte integrasjonstestet uten ekte testkontoer eller testserver.

## Rettelse i v4.2: nettleserens Origin: null

I v4.1 ble `Referrer-Policy: no-referrer` sendt på alle sider. Chromium
sender da `Origin: null` på vanlige HTML-skjemainnsendinger (POST), som
CSRF-/opprinnelseskontrollen avviser. I v4.2 er headeren endret til
`Referrer-Policy: same-origin`. Dette tillater vanlige skjemaer fra samme
adresse, men sender ikke Referer-informasjon til fremmede nettsteder.
`Origin: null` blir fremdeles avvist. Både den eksisterende CSRF-token-
kontrollen og SameSite-cookies er beholdt.

Oppdater som vanlig med `docker compose up --build -d`; databasen i
Docker-volumet beholdes.

## Feilsøking av HTTP 403 ved innlogging

Hvis siden viser «Ugyldig opprinnelse», sjekk `docker compose logs --tail=50 christmas-gift-tag`.
Versjon 4.2 logger avvist `Origin` og HTTP `Host` (uten passord). Ved vanlig
lokal tilgang skal begge være `http://localhost:8080` / `localhost:8080`
(eller tilsvarende `127.0.0.1`). `BASE_URL` brukes til QR-lenker og OAuth,
ikke som en ubetinget Origin-verdi.

For å teste uten å oppgi ekte brukernavn eller passord:

```powershell
curl.exe -i -X POST http://localhost:8080/login -H "Origin: http://localhost:8080" -d "username=probe&password=probe"
```

`401 Unauthorized` betyr at Origin ble godtatt og passordet ble avvist,
mens `403 Forbidden` betyr at Origin fortsatt ble avvist.
