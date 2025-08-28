import tkinter as tk
from tkinter import ttk, messagebox
import random
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from ttkthemes import ThemedTk

# ---------------- Firewall Rules ----------------
firewall_rules = {
    "block_ports": [21, 53, 8801],
    "block_protocols": ["UDP"],
    "allow_protocols": ["TCP"],
    "block_ips": ["192.168.1.10"]
}

# Stats
packet_stats = {"allowed": 0, "blocked": 0}
# Data for the live graph
graph_data = {"time": [], "allowed": [], "blocked": []}
graph_interval = 2 # seconds

# GUI Setup
root = ThemedTk(theme="arc")
root.title("Interactive Firewall Simulator")
root.geometry("1100x700")
root.config(bg="#f7f7f7")

# ---------------- Functions ----------------
def random_ip():
    """Generate a fake random IP address"""
    return f"192.168.{random.randint(0, 1)}.{random.randint(1, 254)}"

def log_packet(time_stamp, src_ip, dst_ip, protocol, port, action):
    """Insert packet into the table"""
    packet_table.insert("", "end", values=(time_stamp, src_ip, dst_ip, protocol, port, action))

def check_packet(src_ip, dst_ip, protocol, port):
    """Simulate firewall decision"""
    if src_ip in firewall_rules["block_ips"] or dst_ip in firewall_rules["block_ips"]:
        packet_stats["blocked"] += 1
        return "❌ BLOCKED (IP Rule)"
    elif protocol in firewall_rules["block_protocols"]:
        packet_stats["blocked"] += 1
        return "❌ BLOCKED (Protocol Rule)"
    elif port in firewall_rules["block_ports"]:
        packet_stats["blocked"] += 1
        return "❌ BLOCKED (Port Rule)"
    elif protocol in firewall_rules["allow_protocols"]:
        packet_stats["allowed"] += 1
        return "✅ ALLOWED"
    else:
        packet_stats["blocked"] += 1
        return "⚠️ BLOCKED (Default)"

def simulate_packets():
    """Generate random packets continuously"""
    while running.get():
        src_ip = random_ip()
        dst_ip = random_ip()
        protocol = random.choice(["TCP", "UDP", "ICMP"])
        port = random.randint(20, 9000)
        action = check_packet(src_ip, dst_ip, protocol, port)
        log_packet(time.strftime("%H:%M:%S"), src_ip, dst_ip, protocol, port, action)
        update_stats()
        time.sleep(1.5)

def start_simulation():
    if not running.get():
        running.set(True)
        threading.Thread(target=simulate_packets, daemon=True).start()
        anim.event_source.start()

def stop_simulation():
    running.set(False)
    anim.event_source.stop()

def clear_logs():
    """Clears all entries from the packet table and resets stats"""
    for item in packet_table.get_children():
        packet_table.delete(item)
    packet_stats["allowed"] = 0
    packet_stats["blocked"] = 0
    update_stats()
    # Clear graph data
    graph_data["time"].clear()
    graph_data["allowed"].clear()
    graph_data["blocked"].clear()

def filter_logs(event=None):
    """Filters the packet table based on user input"""
    search_term = filter_entry.get().lower()
    search_type = filter_var.get()

    packet_table.delete(*packet_table.get_children())
    
    for _, row_data in all_packets:
        value_to_check = ""
        if search_type == "Source IP":
            value_to_check = row_data[1]
        elif search_type == "Destination IP":
            value_to_check = row_data[2]
        elif search_type == "Protocol":
            value_to_check = row_data[3]
        elif search_type == "Port":
            value_to_check = str(row_data[4])
        elif search_type == "Action":
            value_to_check = row_data[5]

        if search_term in value_to_check.lower():
            packet_table.insert("", "end", values=row_data)

def add_rule():
    """Add a new block rule"""
    choice = rule_type_var.get()
    value = rule_value_entry.get().strip()
    
    if choice == "Port":
        if not value.isdigit():
            messagebox.showerror("Error", "Please enter a numeric port!")
            return
        value = int(value)
        if value not in firewall_rules["block_ports"]:
            firewall_rules["block_ports"].append(value)
            messagebox.showinfo("Rule Added", f"Blocked Port {value}")
    elif choice == "Protocol":
        value = value.upper()
        if value not in firewall_rules["block_protocols"]:
            firewall_rules["block_protocols"].append(value)
            messagebox.showinfo("Rule Added", f"Blocked Protocol {value}")
    elif choice == "IP":
        if value not in firewall_rules["block_ips"]:
            firewall_rules["block_ips"].append(value)
            messagebox.showinfo("Rule Added", f"Blocked IP {value}")
    update_rules_display()

def remove_rule():
    """Remove a block rule"""
    choice = rule_type_var.get()
    value = rule_value_entry.get().strip()
    
    if choice == "Port" and value.isdigit():
        value = int(value)
        if value in firewall_rules["block_ports"]:
            firewall_rules["block_ports"].remove(value)
            messagebox.showinfo("Rule Removed", f"Port {value} unblocked")
    elif choice == "Protocol":
        value = value.upper()
        if value in firewall_rules["block_protocols"]:
            firewall_rules["block_protocols"].remove(value)
            messagebox.showinfo("Rule Removed", f"Protocol {value} unblocked")
    elif choice == "IP":
        if value in firewall_rules["block_ips"]:
            firewall_rules["block_ips"].remove(value)
            messagebox.showinfo("Rule Removed", f"IP {value} unblocked")
    update_rules_display()

def update_rules_display():
    rules_text.delete("1.0", tk.END)
    rules_text.insert(tk.END, f"Blocked Ports: {firewall_rules['block_ports']}\n")
    rules_text.insert(tk.END, f"Blocked Protocols: {firewall_rules['block_protocols']}\n")
    rules_text.insert(tk.END, f"Allowed Protocols: {firewall_rules['allow_protocols']}\n")
    rules_text.insert(tk.END, f"Blocked IPs: {firewall_rules['block_ips']}\n")

def update_stats():
    stats_label.config(text=f"✅ Allowed: {packet_stats['allowed']}   ❌ Blocked: {packet_stats['blocked']}")

def change_protocol_policy():
    """Toggles the protocol policy between allowing TCP/blocking UDP and vice versa"""
    if "TCP" in firewall_rules["allow_protocols"]:
        firewall_rules["allow_protocols"] = ["UDP"]
        firewall_rules["block_protocols"] = ["TCP"]
        messagebox.showinfo("Policy Change", "Protocol policy changed: Allowing UDP, Blocking TCP.")
        protocol_policy_button.config(text="Allow TCP / Block UDP")
    else:
        firewall_rules["allow_protocols"] = ["TCP"]
        firewall_rules["block_protocols"] = ["UDP"]
        messagebox.showinfo("Policy Change", "Protocol policy changed: Allowing TCP, Blocking UDP.")
        protocol_policy_button.config(text="Allow UDP / Block TCP")
    update_rules_display()

def update_graph(i):
    """Updates the matplotlib graph with live data"""
    graph_data["time"].append(time.time())
    graph_data["allowed"].append(packet_stats["allowed"])
    graph_data["blocked"].append(packet_stats["blocked"])

    # Keep a fixed number of data points for visibility
    max_points = 20
    if len(graph_data["time"]) > max_points:
        graph_data["time"] = graph_data["time"][-max_points:]
        graph_data["allowed"] = graph_data["allowed"][-max_points:]
        graph_data["blocked"] = graph_data["blocked"][-max_points:]

    ax.clear()
    ax.set_title("Live Packet Stats")
    ax.plot(graph_data["time"], graph_data["allowed"], label="Allowed", color="green")
    ax.plot(graph_data["time"], graph_data["blocked"], label="Blocked", color="red")
    ax.legend()
    ax.tick_params(axis='x', rotation=45)
    plt.tight_layout()

# ---------------- Controls ----------------
btn_frame = ttk.Frame(root)
btn_frame.pack(pady=5)

ttk.Button(btn_frame, text="▶ Start Simulation", command=start_simulation, style="Accent.TButton").grid(row=0, column=0, padx=5)
ttk.Button(btn_frame, text="⏸ Stop Simulation", command=stop_simulation, style="TButton").grid(row=0, column=1, padx=5)
ttk.Button(btn_frame, text="🧹 Clear Logs", command=clear_logs, style="TButton").grid(row=0, column=2, padx=5)
protocol_policy_button = ttk.Button(btn_frame, text="Allow UDP / Block TCP", command=change_protocol_policy)
protocol_policy_button.grid(row=0, column=3, padx=5)

# Rule management
rule_frame = ttk.LabelFrame(root, text="Firewall Rules", padding=10)
rule_frame.pack(pady=10)

rule_type_var = tk.StringVar(value="Port")
ttk.Combobox(rule_frame, textvariable=rule_type_var, values=["Port", "Protocol", "IP"], width=10, state="readonly").grid(row=0, column=0, padx=5)

rule_value_entry = ttk.Entry(rule_frame, width=15)
rule_value_entry.grid(row=0, column=1, padx=5)

ttk.Button(rule_frame, text="Add Rule", command=add_rule).grid(row=0, column=2, padx=5)
ttk.Button(rule_frame, text="Remove Rule", command=remove_rule).grid(row=0, column=3, padx=5)

rules_text = tk.Text(rule_frame, height=5, width=80)
rules_text.grid(row=1, column=0, columnspan=4, pady=5)

update_rules_display()

# ---------------- Main Display Area ----------------
main_frame = ttk.Frame(root)
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Left: Packet Table
table_frame = ttk.LabelFrame(main_frame, text="Packet Log")
table_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

filter_frame = ttk.Frame(table_frame)
filter_frame.pack(fill="x", padx=5, pady=5)
ttk.Label(filter_frame, text="🔎 Filter By:").pack(side="left", padx=5)
filter_var = tk.StringVar(value="Source IP")
ttk.Combobox(filter_frame, textvariable=filter_var, values=["Source IP", "Destination IP", "Protocol", "Port", "Action"], state="readonly").pack(side="left", padx=5)
filter_entry = ttk.Entry(filter_frame)
filter_entry.pack(side="left", fill="x", expand=True, padx=5)
filter_entry.bind("<KeyRelease>", filter_logs)

columns = ("Time", "Source IP", "Destination IP", "Protocol", "Port", "Action")
packet_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=120)
packet_table.pack(fill="both", expand=True)

# Right: Visualization
viz_frame = ttk.LabelFrame(main_frame, text="Live Traffic Visualization")
viz_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

fig, ax = plt.subplots(figsize=(6, 4))
canvas = FigureCanvasTkAgg(fig, master=viz_frame)
canvas.get_tk_widget().pack(fill="both", expand=True)

# Stats label
stats_label = ttk.Label(root, text="✅ Allowed: 0   ❌ Blocked: 0", font=("Arial", 12))
stats_label.pack(pady=5)

# Running state
running = tk.BooleanVar(value=False)
all_packets = []

# Override the log_packet function to store packets
original_log_packet = log_packet
def log_and_store_packet(time_stamp, src_ip, dst_ip, protocol, port, action):
    packet_data = (time_stamp, src_ip, dst_ip, protocol, port, action)
    all_packets.append((len(all_packets), packet_data))
    if not filter_entry.get():
        packet_table.insert("", "end", values=packet_data)
log_packet = log_and_store_packet

# Start the matplotlib animation, but keep it stopped initially
anim = FuncAnimation(fig, update_graph, interval=graph_interval * 1000, blit=False, cache_frame_data=False)
anim.event_source.stop()

# Run GUI
root.mainloop()

