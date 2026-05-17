# Praktični dio: Simulacija Incident Response (Brute-Force napad)

Ova aplikacija predstavlja praktični dodatak seminarskom radu na temu **Upravljanje sigurnosnim incidentima (Incident Response Plan)**.

## Šta aplikacija demonstrira?
Aplikacija demonstrira tehničke aspekte iz poglavlja 4 ("Secure by Design" i pravilno logiranje incidenata), kroz simulaciju faza iz NIST IRP životnog ciklusa:
1. **Detekcija i analiza**: Kroz ugrađeni `Serilog`, aplikacija bilježi (logira) svaki neuspješan pokušaj prijave. Ne logiraju se lozinke u čistom tekstu.
2. **Izolacija (Containment)**: Ukoliko algoritam detektuje 5 uzastopnih promašaja sa iste IP adrese, aplikacija eskalira događaj u **Kritični incident**, automatski izolira (blokira) tu IP adresu i odbija dalje HTTP zahtjeve sa statusom `403 Forbidden`.

## Kako pokrenuti i testirati?
1. Pokrenite API komandom: `dotnet run`
2. Otvorite fajl `test_napad.http` (iz Visual Studio ili VS Code).
3. Pokrenite drugi endpoint (Neuspješna prijava) **5 puta zaredom**.
4. Pri šestom pokušaju dobit ćete poruku da je IP adresa blokirana (Status 403).
5. Otvorite generisani fajl `incident_logs.txt` u root folderu i pregledajte kako izgleda struktuirani log incidenta, spreman za unos u SIEM sisteme.