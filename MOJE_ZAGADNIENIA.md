# Moje zagadnienia — Osoba A

Wybrane z `ARCHITECTURE.md` zgodnie z zakresem Osoby A w `TEAM_TASKS_DIVISION.md`.

## 2. Widok wysokiego poziomu

```mermaid
flowchart TD
    Client["🖥️ Aplikacja kliencka"]
    PipelineProxy["🛡️ Pipeline Proxy\n(wzorzec Proxy)"]
    InboundPipeline["⚙️ Inbound Pipeline\n(Pipes & Filters)"]
    Vault["🔐 Tokenization Vault\n(Proxy + Memento)"]
    ResidencyGate["🌍 Residency Gate\nPolicy Engine"]
    ExtLLM["🤖 Zewnętrzny LLM\n(OpenAI / Anthropic / ...)"]
    OutboundPipeline["⚙️ Outbound Pipeline\n(Pipes & Filters)"]
    AuditLog["📋 Immutable Audit Log"]
    KeyManagement["🗝️ Key Management Service\n(KMS)"]

    Client -->|"zapytanie z PII"| PipelineProxy
    PipelineProxy --> InboundPipeline

    InboundPipeline -->|"wykrywanie PII"| D1["🔍 Detector Filter"]
    D1 -->|"strategia maskowania"| D2["🎭 Anonymization Filter\n(Strategy)"]
    D2 -->|"ocena ryzyka re-ID"| D3["📊 Re-ID Risk Filter"]
    D3 -->|"weryfikacja residency"| ResidencyGate

    ResidencyGate -->|"blokada jeśli naruszenie"| AuditLog
    ResidencyGate -->|"dozwolone"| ExtLLM

    ExtLLM -->|"odpowiedź z tokenami"| OutboundPipeline
    OutboundPipeline -->|"OutputPIIDetector: skan przed de-tokenizacją"| Vault
    Vault -->|"żądanie klucza"| KeyManagement
    Vault -->|"log de-tokenizacji"| AuditLog
    Vault -->|"przywrócone PII"| PipelineProxy
    PipelineProxy -->|"odpowiedź dla uprawnionego"| Client

    style Vault fill:#ffd6a5,stroke:#e07a00
    style ResidencyGate fill:#d0f0c0,stroke:#2d6a4f
    style AuditLog fill:#e8d5f5,stroke:#6a2d8f
    style KeyManagement fill:#ffd6d6,stroke:#8f2d2d
```

### Kluczowe zasady projektu

| Zasada | Realizacja |
|--------|-----------|
| **Minimalizacja danych** | Tylko niezbędne atrybuty PII trafiają do Vault; reszta jest usuwana |
| **Privacy by Design** | Anonimizacja jest pierwszym krokiem pipeline'u, nie ostatnim |
| **Separation of Concerns** | Każdy filtr ma jedną odpowiedzialność |
| **Zero Trust** | Każde żądanie de-tokenizacji wymaga jawnego uwierzytelnienia i autoryzacji |
| **Audit Everything** | Wszystkie operacje na tokenach są logowane niezależnie od powodzenia |

---

### 3.1 Pipes & Filters

**Rola:** Główna struktura pipeline'u przetwarzania tekstu.

Każdy filtr jest niezależną jednostką przetwarzającą, która konsumuje `PipelineContext` i zwraca zmodyfikowany `PipelineContext`. Filtry mogą:
- **przepuszczać** dane bez zmian (pass-through),
- **transformować** dane (anonimizacja),
- **wzbogacać** dane (metadane, ryzyko),
- **blokować** przepływ (hard-stop z audytem).

```mermaid
flowchart LR
    IN["📥 Wejście\n(surowy tekst)"] --> F1
    F1["🔍 LanguageDetector\nFilter"] --> F2
    F2["🔍 PIIDetector\nFilter"] --> F3
    F3["📊 RiskAssessment\nFilter"] --> F4
    F4["🎭 Anonymization\nFilter"] --> F5
    F5["🌍 ResidencyPolicy\nFilter"] --> F6
    F6["📋 AuditContext\nFilter"] --> OUT["📤 Wyjście\n(zanonimizowany tekst)"]

    LLM["🤖 Odpowiedź LLM\n(z tokenami)"] --> OF1
    OF1["🔍 OutputPIIDetector\nFilter"] --> OF2["🔐 ResponseRestorer\n(Memento + Vault)"]
    OF2 --> OOUT["📤 Odpowiedź\n(po kontroli PII)"]

    style F2 fill:#fff3cd,stroke:#d4a017
    style F4 fill:#d0f0c0,stroke:#2d6a4f
    style F5 fill:#d6eaf8,stroke:#1a5276
    style OF1 fill:#fff3cd,stroke:#d4a017
    style OF2 fill:#ffd6a5,stroke:#e07a00
```

Outbound Pipeline zawiera `OutputPIIDetector`, uruchamiany przed `ResponseRestorer`, de-tokenizacją oraz odwróceniem Memento. Filtr analizuje także odpowiedzi częściowe i może wykonać hard-stop, redakcję lub przekazać wynik do audytu, zanim jakakolwiek wartość zostanie przywrócona z Vault.

**Kluczowe właściwości:**

- **Kolejność filtrów jest deterministyczna** — `LanguageDetector` musi działać przed `PIIDetector`, bo reguły wykrywania PESEL różnią się od SSN.
- **Short-circuit semantics** — filtr `ResidencyPolicy` może przerwać łańcuch i zwrócić błąd bez dalszego przetwarzania.
- **Konfigurowalne łańcuchy** — `PipelineBuilder` (patrz §3.3) pozwala składać różne łańcuchy dla różnych kontekstów (np. pipeline dla danych medycznych vs. finansowych).

```
interface Filter {
    process(context: PipelineContext): PipelineContext | HardStop
}

interface Pipe {
    addFilter(filter: Filter): Pipe
    execute(input: RawInput): PipelineResult
}
```

---

### 3.3 Builder

**Rola:** Budowanie skonfigurowanego pipeline'u krok po kroku, z walidacją spójności.

`PipelineBuilder` enkapsuluje złożoną logikę tworzenia pipeline'u:
- sprawdza, że wymagane filtry (np. `PIIDetector` przed `AnonymizationFilter`) są obecne w odpowiedniej kolejności,
- weryfikuje zgodność polityk (np. jeśli dane to PHI, wymaga silniejszej strategii),
- tworzy niemutowalny obiekt `Pipeline` gotowy do użycia.

```mermaid
flowchart LR
    B["PipelineBuilder"]
    B -->|"forDataClass(MEDICAL)"| B1["+ MedicalPIIDetector\n+ PHIExtractor"]
    B -->|"withResidencyPolicy(EU_ONLY)"| B2["+ ResidencyFilter(EU)"]
    B -->|"withAnonymizationStrategy\n(TOKENIZE)"| B3["+ TokenizationStrategy"]
    B -->|"withAuditLevel(FULL)"| B4["+ DetailedAuditFilter"]
    B -->|"build()"| P["✅ Immutable\nPipeline"]
```

```
PipelineBuilder
    .forDataClass(DataClass.MEDICAL)
    .withResidencyPolicy(ResidencyPolicy.EU_ONLY)
    .withAnonymizationStrategy(StrategyType.TOKENIZE, config)
    .withReIdRiskThreshold(0.05)
    .withAuditLevel(AuditLevel.FULL)
    .build()
```

**Dlaczego Builder, nie Factory?**  
Factory tworzy jeden dobrze znany obiekt. Builder jest niezbędny, gdy produkt wymaga **wielu kroków konfiguracji z walidacją między nimi** — np. nie można ustawić `withAuditLevel(NONE)` przy `DataClass.MEDICAL` (naruszenie GDPR).

---

### 3.5 Memento

**Rola:** Zachowanie i przywracanie stanu pipeline'u w celu bezpiecznej rekonstrukcji kontekstu.

Memento służy dwóm celom:

#### A. Przywracanie tokenów w odpowiedzi LLM

`PipelineContext` (Originator) tworzy `PipelineMemento` po fazie anonimizacji. Ten snapshot zawiera mapowanie `token → metadane`, które pozwala `ResponseRestorer` (Caretaker) przywrócić oryginalne wartości w odpowiedzi LLM **bez ponownego dostępu do Vault** dla każdego tokenu z osobna — jeden call, atomowe przywrócenie.

#### B. Odtwarzanie stanu po awarii

Przy przerwaniu sesji (np. timeout LLM) system może odtworzyć stan z Memento i wznowić od momentu wysłania do LLM, bez ponownej anonimizacji (która byłaby niedeterministyczna przy tokenach sekwencyjnych).

#### C. Dynamic Memento Expansion w sesji agentowej

W sesji agentowej `PipelineMemento` jest rozszerzalny i może atomowo dopisywać nowe tokeny powstałe podczas wykonywania narzędzi. Gdy `ToolExecutionMiddleware` pobierze z Vault wartość potrzebną do zapytania (np. `Jan Kowalski`), wynik z bazy danych jest natychmiast tokenizowany w Vault/Memento (np. `1990-01-01` → `<DATE_1>`), a wpis `<DATE_1>` zostaje dodany do istniejącego `tokenMap` tej samej sesji. Memento nie ujawnia wartości jawnej ani LLM, ani komponentom przechowującym snapshot.

Rozszerzenie jest wersjonowane i wykonywane przed zwróceniem wyniku narzędzia do LLM, dzięki czemu `ResponseRestorer` korzystający z końcowego snapshotu przywraca zarówno tokeny pierwotnego promptu (`<PERSON_1>`), jak i tokeny wygenerowane dynamicznie przez narzędzie (`<DATE_1>`). Operacja wymaga kontroli integralności, zgodności `sessionId` oraz audytu tak jak początkowa anonimizacja.

```mermaid
stateDiagram-v2
    [*] --> Processing : wejście użytkownika
    Processing --> Anonymized : filtr anonimizacji + tworzenie Memento
    Anonymized --> SentToLLM : Residency OK
    SentToLLM --> WaitingForLLM
    WaitingForLLM --> ResponseReceived : sukces
    WaitingForLLM --> Recovering : timeout lub błąd
    Recovering --> SentToLLM : retry z Memento
    ResponseReceived --> Restored : Caretaker przywraca z Memento + Vault
    Restored --> [*] : odpowiedź do klienta
```

```
PipelineMemento {
    sessionId:      UUID
    tokenMap:       Map<Token, EntityMetadata>   // NIE zawiera oryginalnych wartości
    version:        int                           // wersja po każdym rozszerzeniu
    appliedFilters: List<FilterRecord>
    timestamp:      Instant
    checksum:       bytes   // integralność snapshotu
}
```

> **Ważne:** Memento **nigdy nie przechowuje oryginalnych wartości PII** — tylko tokeny i metadane. Oryginalne wartości żyją wyłącznie w Vault (zaszyfrowane), również dla tokenów dodanych dynamicznie podczas wywołania narzędzia.

---

## 4. Komponenty systemu

```mermaid
flowchart TD
    subgraph ClientLayer["Client Layer"]
        App["Aplikacja kliencka"]
        SDK["Privacy Pipeline SDK"]
    end

    subgraph PipelineLayer["Pipeline Layer"]
        ProxyComp["PipelineProxy (entry point)"]
        InPipe["Inbound Pipeline"]
        OutPipe["Outbound Pipeline"]
        BuilderComp["PipelineBuilder"]
    end

    subgraph DetectionLayer["Detection Layer"]
        LangDet["LanguageDetector (PL/EN/DE...)"]
        PIIDet["PIIDetector (reguły + NER ML)"]
        PHIDet["PHIDetector (HL7/FHIR aware)"]
        ReIdDet["ReIdRiskAnalyzer (k-anonimowość)"]
        OutPIIDet["OutputPIIDetector"]
    end

    subgraph AnonLayer["Anonymization Layer"]
        AnonFilter["AnonymizationFilter"]
        StratSel["StrategySelector"]
        TokStrat["TokenizationStrategy"]
        MaskStrat["MaskingStrategy"]
        GenStrat["GeneralizationStrategy"]
        SynStrat["SynthesisStrategy"]
    end

    subgraph VaultLayer["Vault Layer"]
        VProxy["VaultProxy (AuthN/AuthZ/Audit)"]
        VCore["VaultCore (encrypt/decrypt)"]
        TokenDB[("TokenDB (encrypted records)")]
    end

    subgraph KeyMgmt["Key Management"]
        KMS["KMS (klucze szyfrowania)"]
        KeyRotation["KeyRotation Scheduler"]
    end

    subgraph PolicyLayer["Policy Layer"]
        ResPolicy["ResidencyPolicyEngine"]
        DataClass["DataClassifier"]
        RetPolicy["RetentionPolicyEngine"]
        RetWorker["RetentionWorker (asynchroniczny purge)"]
    end

    subgraph AuditLayer["Audit Layer"]
        AuditLogDB[("Immutable Audit Log")]
        AuditWriter["AuditWriter (append-only)"]
        AlertingComp["Alerting (SIEM integration)"]
    end

    App --> SDK --> ProxyComp
    ProxyComp --> InPipe --> LangDet --> PIIDet --> PHIDet --> ReIdDet
    ReIdDet --> AnonFilter
    AnonFilter --> StratSel
    StratSel --> TokStrat & MaskStrat & GenStrat
    TokStrat --> VProxy --> VCore --> TokenDB
    SynStrat --> VProxy
    VCore --> KMS
    KeyRotation --> KMS

    InPipe --> ResPolicy
    ResPolicy --> DataClass
    RetPolicy --> TokenDB
    RetPolicy --> RetWorker --> TokenDB
    OutPipe --> OutPIIDet --> VProxy

    VProxy --> AuditWriter --> AuditLogDB
    AuditLogDB --> AlertingComp
```

### Opis kluczowych komponentów

| Komponent | Odpowiedzialność | Wzorzec |
|-----------|-----------------|---------|
| `PipelineProxy` | Pojedynczy punkt wejścia; zarządza sesjami, Memento oraz normalizuje tekst i obiekty `ToolCall` / `FunctionCall` JSON | Proxy, Facade |
| `Inbound Pipeline` | Przetwarza `RawInput` oraz ustrukturyzowane wywołania narzędzi; tokenizuje argumenty `name`/`arguments` przed przekazaniem do LLM | Pipes & Filters |
| `PIIDetector` | Wykrywa encje PII kombinując reguły regex (PESEL, NIP) + model NER | Filter |
| `OutputPIIDetector` | Skanuje odpowiedź LLM pod kątem PII wygenerowanego lub ujawnionego przez model, przed de-tokenizacją | Filter |
| `AnonymizationFilter` | Deleguje do strategii wybranej przez `StrategySelector` | Filter + Strategy |
| `VaultProxy` | Enforce AuthN/AuthZ/RateLimit przed każdą operacją na Vault | Proxy |
| `VaultCore` | Szyfruje/deszyfruje wartości PII, zarządza cyklem życia tokenów | — |
| `RetentionWorker` | Asynchronicznie usuwa wygasłe rekordy tokenów po TTL sesji i audytuje wykonanie purge | Worker |
| `ResidencyPolicyEngine` | Sprawdza, czy docelowy LLM jest w dozwolonej strefie geograficznej | Policy |
| `ReIdRiskAnalyzer` | Oblicza ryzyko re-identyfikacji metodą k-anonimowości | Filter |
| `PipelineBuilder` | Tworzy i waliduje konfigurację pipeline'u | Builder |
| `AuditWriter` | Append-only zapis do niezmiennego logu (WORM storage / blockchain hash) | — |

`PipelineProxy` i `Inbound Pipeline` nie zakładają, że wejście jest wyłącznie typu `str`. Dla obiektu `ToolCall` / `FunctionCall` zachowują strukturę JSON, identyfikator wywołania, nazwę funkcji oraz schemat argumentów, a anonimizacji podlegają wartości w `arguments` (rekurencyjnie, zgodnie z typem encji). Dzięki temu LLM otrzymuje wyłącznie zanonimizowaną definicję i parametry narzędzia, natomiast middleware może przechwycić ustrukturyzowany call przed wykonaniem.

```
ToolCall {
    id:        UUID
    name:      string
    arguments: JSON          // wartości PII zastąpione tokenami
    sessionId: UUID
}
```

---

## 5. Scenariusze użycia

### 5.1 Pseudonimizacja — happy path

**Wejście:** `"Jan Kowalski, PESEL 90010112345, skarży się na fakturę 7/2026"`

```mermaid
sequenceDiagram
    participant User
    participant Proxy as PipelineProxy
    participant InPipe as Inbound Pipeline
    participant Vault as VaultProxy
    participant LLM as Zewnętrzny LLM
    participant OutPipe as Outbound Pipeline
    participant OutputPII as OutputPIIDetector

    User->>Proxy: query("Jan Kowalski, PESEL 90010112345...")
    Proxy->>InPipe: process(context)

    Note over InPipe: [Filter 1] LanguageDetector - PL
    Note over InPipe: [Filter 2] PIIDetector - PERSON: "Jan Kowalski", PESEL: "90010112345"
    Note over InPipe: [Filter 3] ReIdRiskAnalyzer - LOW
    Note over InPipe: [Filter 4] AnonymizationFilter

    InPipe->>Vault: tokenize("Jan Kowalski", PERSON)
    Vault-->>InPipe: token PERSON_1
    InPipe->>Vault: tokenize("90010112345", PESEL)
    Vault-->>InPipe: token PESEL_1

    Note over InPipe: [Filter 5] ResidencyPolicy - ALLOWED
    Note over InPipe: Tworzenie Memento (snapshot tokenMap)

    InPipe-->>Proxy: "PERSON_1, PESEL_1, skarzy sie na fakture 7/2026"
    Proxy->>LLM: zanonimizowany tekst
    LLM-->>Proxy: "Sprawa PERSON_1 (PESEL_1) dotyczy faktury 7/2026..."

    Proxy->>OutPipe: restore(response, memento)
    OutPipe->>OutputPII: scan(response)
    OutputPII-->>OutPipe: brak nowego PII / tokeny do przywrócenia
    OutPipe->>Vault: deTokenize(PERSON_1, credentials)
    Vault-->>OutPipe: "Jan Kowalski"
    OutPipe->>Vault: deTokenize(PESEL_1, credentials)
    Vault-->>OutPipe: "90010112345"
    OutPipe-->>Proxy: odpowiedź z przywróconymi danymi
    Proxy-->>User: "Sprawa Jana Kowalskiego (PESEL 90010112345)..."
```

**Wynik wysłany do LLM:** `"<PERSON_1>, <PESEL_1>, skarży się na fakturę 7/2026"`  
**Wynik zwrócony użytkownikowi:** oryginalna treść z przywróconymi danymi.

`OutputPIIDetector` działa przed de-tokenizacją i odwróceniem Memento. Wykrywa zarówno PII podchwycone z kontekstu, jak i nowe, zmyślone lub pochodzące z danych treningowych modelu (hallucination / training data leak). W przypadku wykrycia nieoczekiwanego PII odpowiedź jest blokowana albo kierowana do polityki redakcji i audytu; nie może zostać automatycznie wzbogacona o dane z Vault.

---

### 5.6 Rozszerzenie

**Przykład:** Dodanie detektora polskiego numeru IBAN.

**Zmiana wymagana:** tylko nowe implementacje, **żadna modyfikacja istniejącego kodu** (zasada Open/Closed Principle — spełniona przez Pipes & Filters + Strategy).

```mermaid
flowchart LR
    NewDetector["Nowa klasa: PolishIBANDetector\nimplementuje: PIIDetector"] --> Registry
    NewStrategy["Nowa klasa: IBANMaskingStrategy\nimplementuje: AnonymizationStrategy"] --> Registry
    Registry["DetectorRegistry / StrategyRegistry\n(rejestracja przez @Register lub konfigurację)"] --> Builder2
    Builder2["PipelineBuilder (bez zmian!)"] --> Pipeline2["Pipeline (z nowym detektorem)"]
```

**Kontrakt dla nowego detektora:**

```python
interface PIIDetector:
    entityType()         -> EntityType     # np. EntityType.IBAN
    supportedLanguages() -> List[Lang]
    detect(text, lang)   -> List[DetectedEntity]
    confidence()         -> float          # próg pewności
```

**Przykład implementacji:**

```python
@register_detector(entity_type=EntityType.IBAN, priority=100)
class PolishIBANDetector(PIIDetector):
    IBAN_PATTERN = re.compile(
        r'PL\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}'
    )

    def detect(self, text: str, lang: Lang) -> list[DetectedEntity]:
        return [
            DetectedEntity(
                value=m.group(), type=EntityType.IBAN,
                start=m.start(), end=m.end()
            )
            for m in self.IBAN_PATTERN.finditer(text)
        ]
```

## 6. Model bezpieczeństwa

### 6.1 Wykrywanie PII/PHI

System stosuje **podejście wielowarstwowe**:

| Warstwa | Metoda | Przykłady encji |
|---------|--------|----------------|
| **Reguły deterministyczne** | Regex + checksum (Luhn, PESEL modulo) | PESEL, NIP, REGON, IBAN, numer dowodu |
| **NER (Named Entity Recognition)** | Transformer-based (np. fine-tuned HerBERT dla PL) | Imię, nazwisko, adres, organizacja |
| **Kontekstowe reguły** | Słowa kluczowe + proximity | "diagnoza:", "PESEL:", "ur." |
| **PHI (dane medyczne)** | HL7/FHIR-aware parser | Kody ICD-10, nazwy leków, procedury |
| **Cross-entity correlation** | Graf quasi-identyfikatorów | Kombinacje cech demograficznych |

**Priorytety błędów detekcji:**
- **False Negative** (niewykrycie PII) = **krytyczne** — dane trafiają do LLM bez ochrony.
- **False Positive** (nadmierna anonimizacja) = **akceptowalne** — pogarsza jakość odpowiedzi, ale nie narusza prywatności.

Dlatego progi detekcji są celowo **konserwatywne** (wysoka czułość, niższa precyzja).

---

### ADR-001: Tokenizacja jako domyślna strategia dla PII odwracalnego

- **Kontekst:** Musimy móc przywrócić oryginalne dane dla uprawnionych użytkowników.
- **Decyzja:** Domyślna strategia dla danych wymagających przywrócenia to tokenizacja z Vault.
- **Alternatywy:** Szyfrowanie deterministyczne (ryzyko: podatne na frequency analysis); maskowanie (nieodwracalne).
- **Konsekwencje:** Vault staje się single point of failure — wymaga replikacji HA.

### ADR-003: Memento nie przechowuje oryginalnych wartości PII

- **Kontekst:** Memento musi być bezpiecznie przesyłalne między komponentami.
- **Decyzja:** Memento zawiera tylko tokeny i metadane, nigdy oryginalne wartości.
- **Konsekwencje:** De-tokenizacja zawsze wymaga wywołania Vault (brak skrótu). Akceptowalne ze względów bezpieczeństwa.

