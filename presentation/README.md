# Prezentacja CLI — Osoba A (Inbound Pipeline)

Lokalne narzędzie demonstracyjne pokazujące krok po kroku, co dzieje się z promptem (tekst, PDF, `ToolCall`), zanim trafi do zewnętrznego LLM. Ten katalog nie jest przeznaczony do commitowania.

## Uruchomienie interaktywne

```bash
.venv/bin/python presentation/demo_cli.py
```

W trybie interaktywnym wygenerują się dwa przykładowe pliki PDF w `presentation/samples/`:
- `faktura_tekstowa.pdf` — PDF z warstwą tekstową (`FlateDecode`) + ukryte metadane (`XMP`, `/Author`, `/Redact`), które filtr usuwa.
- `skan_bez_ocr.pdf` — PDF będący skanem (`/Subtype /Image`), który uruchamia blokadę **FAIL-CLOSED** (`UnsupportedMediaWithPotentialPIIError`).

## Przykłady uruchomienia z linii poleceń (one-shot)

1. **Zwykły prompt z polskimi danymi (małe litery + odmiana + PESEL + adres):**
   ```bash
   .venv/bin/python presentation/demo_cli.py --prompt "Rozmawiałem z janem kowalskim, PESEL 44051401458, ul. Lipowa 5"
   ```

2. **Prompt + PDF tekstowy (czyszczenie metadanych + ekstrakcja + anonimizacja):**
   ```bash
   .venv/bin/python presentation/demo_cli.py --prompt "Sprawdź fakturę" --pdf presentation/samples/faktura_tekstowa.pdf
   ```

3. **Skan PDF bez OCR (demonstracja FAIL-CLOSED z ADR-009):**
   ```bash
   .venv/bin/python presentation/demo_cli.py --pdf presentation/samples/skan_bez_ocr.pdf
   ```

4. **Dane medyczne kierowane do USA (demonstracja blokady ResidencyPolicyFilter):**
   ```bash
   .venv/bin/python presentation/demo_cli.py --prompt "Pacjent Jan Kowalski, PESEL 44051401458" --data-class MEDICAL --endpoint us
   ```

5. **ToolCall JSON (rekurencyjna anonimizacja argumentów):**
   ```bash
   .venv/bin/python presentation/demo_cli.py --tool-call-json '{"pacjent": "Jan Kowalski", "dane": {"pesel": "44051401458", "limit": 5}}'
   ```
