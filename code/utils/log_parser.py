import os
import re

def get_parsed_alerts(log_path):
    # שמות השדות לפי הסדר ב-DataAggregator
    FIELDS = ["TCP Ports", "TCP SYN", "ARP Req", "ARP Rep", "ICMP Req", "ICMP Rep", "UDP Ports"]
    alerts = []
    
    if not os.path.exists(log_path):
        return alerts

    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        raw_blocks = content.split(" | ALERT | ")
        
        for i in range(1, len(raw_blocks)):
            block = raw_blocks[i]
            prev_block = raw_blocks[i-1]
            timestamp = prev_block.split('\n')[-1].split(' | ')[0]

            # ניקוי בסיסי
            clean_content = block.split('\n202')[0].strip()
            if " | " in clean_content[:15]:
                clean_content = clean_content.split(" | ", 1)[-1]

            # --- זיהוי אנומליה לפי המבנה החדש שלך ---
            if "ANOMALY DETECTED" in clean_content:
                try:
                    # מחלצים את הכתובות (החלק השני בתוך ה-| |)
                    header_match = clean_content.split(" | ")
                    addresses = header_match[1] if len(header_match) > 1 else "Unknown"
                    
                    # חילוץ המערכים בעזרת Regex (מחפש מספרים בתוך [ ])
                    arrays = re.findall(r'\[([\d\.\,\s]+)\]', clean_content)
                    
                    if len(arrays) >= 2:
                        # ניקוי פסיקים ורווחים כדי להפוך לרשימת מספרים
                        avg_vals = arrays[0].replace(',', ' ').split()
                        curr_vals = arrays[1].replace(',', ' ').split()
                        
                        details = []
                        for j in range(len(FIELDS)):
                            val = float(curr_vals[j])
                            base = float(avg_vals[j])
                            
                            if val > 0 or base > 0:
                                # צביעה באדום אם יש חריגה משמעותית
                                color = "style='color: #fca5a5;'" if val > (base * 5 + 2) else ""
                                details.append(f"<span {color}>{FIELDS[j]}: {int(val)}</span> (avg: {base})")
                        
                        display_text = f"<b>Anomaly: {addresses}</b><br>" + " • ".join(details)
                    else:
                        display_text = clean_content.replace(' | ', ' • ')
                except Exception as e:
                    display_text = clean_content.replace(' | ', ' • ')
            
            else:
                # --- טיפול בהתראות רגילות (Ping Sweep וכו') ---
                display_text = clean_content.replace('\\n', ' • ').replace('\n', ' • ')
                display_text = display_text.replace('{', '').replace('}', '').replace("'", "").replace('"', '')
                display_text = ' '.join(display_text.split())

            alerts.append({
                "time": timestamp,
                "content": display_text
            })
            
    except Exception as e:
        print(f"Error parsing log: {e}")
        
    return alerts[::-1]