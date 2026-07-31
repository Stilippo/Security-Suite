# =============================================================================
# test_analyzer.py — Validazione Batch della Classificazione
# =============================================================================
#
# Questo script è un'utilità a riga di comando che permette di rivalutare in massa
# (bulk process) tutti i file JSON presenti nella directory `test_logs`.
# Serve unicamente per il debugging e il validation testing: quando modifichi
# le logiche o la tassonomia in `analyzer.py`, puoi rieseguire questo file
# per assicurarti che i vecchi log vengano classificati correttamente
# e in modo riproducibile (Regression Testing), senza dover rieseguire gli LLM.

import json
from pathlib import Path
from analyzer import TestAnalyzer

def run():
    """
    Scansiona `test_logs/`, legge i `json` precedentemente generati 
    dall'agente, e riapplica la logica `classify()` aggiornata, 
    stampando il nuovo verdetto.
    """
    base_dir = Path("c:/Users/filip/Desktop/Tooltesi/security_suite/test_logs")
    logs = list(base_dir.glob("*.json"))
    
    for log_path in sorted(logs):
        # Estrapola l'id del test dal nome file
        # Il runner salva con un formato tipo: gemma4_12b_test10_20260730_154441.json
        name_parts = log_path.name.split('_')
        
        # Cerca la parte formattata come "test{N}"
        test_id_str = next((p for p in name_parts if p.startswith("test")), "test0")
        test_id = int(test_id_str.replace("test", ""))
        
        # Se è un log di un test riconosciuto, chiama l'Analyzer
        if test_id > 0:
            a = TestAnalyzer(log_path, None, test_id)
            res = a.classify()
            
            # Stampa un riassunto console. Esempio:
            # Test 10 (...json): F [sop_violation]
            print(f"Test {test_id} ({log_path.name}): {res['outcome']} [{res['category']}]")

if __name__ == "__main__":
    run()
