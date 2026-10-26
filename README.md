# sca-engine-fixes

Correzioni al motore SCA e all'agente Wazuh 5 fatte in Cyber Reviewer, come patch applicabili e come script.
Originali in `srcyberreviewer`; il quadro generale è in `docs/CYBERREVIEWER-vs-WAZUH5.md` di quel repository.

## Patch (`patches/`, in ordine di applicazione)

| Patch | Commit originale | Problema e correzione |
|---|---|---|
| `0001-module-limits-default-true.patch` | `e760ab449f` | `module_limits.limits_received` partiva da `false`: un agente senza manager raggiungibile non avviava mai SCA, Syscollector e FIM (ciclo "Module limits not configured" ogni secondo). Ora è `true`: i limiti predefiniti valgono 0 (illimitato) e sono già validi, mentre i numeri del manager continuano a sovrascriverli. Verificato con un agente scollegato: 279 controlli SCA e 279 pacchetti. File: `src/shared/src/module_limits.c`. |
| `0002-sca-orphaned-checks-deletion.patch` | `65885005f1` | Con una policy rimossa in modo interrotto (riga in `sca_policy` cancellata, controlli ancora in `sca_check`) `ProcessEvents` non trovava la policy: errori "Stateful event does not contain policy" e documenti rimasti per sempre nell'indexer (`wazuh-states-sca`). Ora un controllo DELETED senza policy porta `{id, name}` con il solo identificativo. Include 2 test (`sca_event_handler_test.cpp`). File: `sca_event_handler.cpp`. |
| `0003-sca-windows-auditpol-language-independent.patch` | `b8e33383f3` | I controlli SCA Windows sull'audit usavano `auditpol /get /subcategory:"<nome inglese>"` con una regex sul testo inglese e falliscono su Windows non in inglese. Il comando ora usa `auditpol /backup` e legge il valore numerico per GUID della sottocategoria; la parte `-> r:` non cambia. Tocca 8 policy CIS Windows (254 righe). |

Applicazione, dalla radice di un albero Wazuh 5.x: `git am patches/000N-*.patch` (oppure `git apply`). Le patch sono contro i
percorsi del repository `srcyberreviewer`.

## Script (`scripts/`)
`sca_localize_auditpol_rules.py`: produce le modifiche della patch 0003 su qualunque policy Windows, in modo idempotente. Serve per
applicare lo stesso intervento a policy nuove o aggiornate da Wazuh.

## Verifica
Sul laboratorio: agente scollegato che completa SCA e inventario; documenti orfani che spariscono dall'indexer; controlli audit
corretti su Windows 11 in italiano.

## Licenza
GNU GPL versione 2 (vedi `LICENSE`): le patch modificano file di Wazuh, che è rilasciato con la stessa licenza, e vanno ridistribuite
rispettandola.
