from textual import on
from textual.app import App, ComposeResult
from textual.containers import HorizontalGroup
from textual.widgets import Button, Select, Tabs, RichLog, Header

import os
import socket


GREEN = "[green]"
BLUE = "[blue]"
YELLOW = "[yellow]"
RED = "[red]"


class FrameParser:
    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.d_mac = None
        self.s_mac = None
        self.ether_type = None

        self.version = None
        self.ihl = None
        self.qos = None
        self.total_length = None
        self.identification = None
        self.ip_flags = None
        self.fragment_offset = None
        self.ttl = None
        self.protocol = None
        self.header_checksum = None
        self.s_ip = None
        self.d_ip = None
        self.ip_options = None

        self.s_port = None
        self.d_port = None
        self.sequence_number = None
        self.acknowledgment_number = None
        self.data_offset = None
        self.tcp_flags = None
        self.window_size = None
        self.checksum = None
        self.urgent_pointer = None
        self.tcp_options = None

        self.data = None

        self.parse_all()

    def parse_eth(self):
        self.d_mac = self.raw_data[0:6]
        self.s_mac = self.raw_data[6:12]
        self.ether_type = self.raw_data[12:14]

    def parse_ip(self):
        first_byte = self.raw_data[14]
        self.version = first_byte >> 4
        self.ihl = first_byte & 0x0F
        self.qos = self.raw_data[15]
        self.total_length = int.from_bytes(self.raw_data[16:18], "big")
        self.identification = self.raw_data[18:20]
        self.ip_flags = self.raw_data[20] >> 5
        self.fragment_offset = ((self.raw_data[20] & 0x1F) << 8) | self.raw_data[21]
        self.ttl = self.raw_data[22]
        self.protocol = self.raw_data[23]
        self.header_checksum = self.raw_data[24:26]
        self.s_ip = self.raw_data[26:30]
        self.d_ip = self.raw_data[30:34]

        if self.ihl:
            ip_header_len = self.ihl * 4
        else:
            ip_header_len = 20

        self.ip_options = self.raw_data[34 : 14 + ip_header_len]

    def parse_tcp(self):
        if self.ihl:
            ip_header_len = self.ihl * 4
        else:
            ip_header_len = 20

        tcp_start = 14 + ip_header_len

        self.s_port = int.from_bytes(self.raw_data[tcp_start : tcp_start + 2], "big")
        self.d_port = int.from_bytes(self.raw_data[tcp_start + 2 : tcp_start + 4], "big")
        self.sequence_number = int.from_bytes(self.raw_data[tcp_start + 4 : tcp_start + 8], "big")
        self.acknowledgment_number = int.from_bytes(self.raw_data[tcp_start + 8 : tcp_start + 12], "big")
        self.data_offset = self.raw_data[tcp_start + 12] >> 4
        self.tcp_flags = self.raw_data[tcp_start + 13]
        self.window_size = int.from_bytes(self.raw_data[tcp_start + 14 : tcp_start + 16], "big")
        self.checksum = self.raw_data[tcp_start + 16 : tcp_start + 18]
        self.urgent_pointer = self.raw_data[tcp_start + 18 : tcp_start + 20]

        if self.data_offset:
            tcp_header_len = self.data_offset * 4
        else:
            tcp_header_len = 20

        self.tcp_options = self.raw_data[tcp_start + 20 : tcp_start + tcp_header_len]

        app_start = tcp_start + tcp_header_len
        self.data = self.raw_data[app_start:]

    def parse_all(self):
        self.parse_eth()
        self.parse_ip()
        self.parse_tcp()


class FrameSniffer:
    def __init__(self, interface):
        self.interface = interface

    def capture_frame(self):
        try:
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as sock:
                sock.bind((self.interface, 0))
                raw_frame, _ = sock.recvfrom(65535)
                return raw_frame
        except PermissionError:
            print("Run az root pls")
            exit()


def get_layer_color(index, ip_start, tcp_start, data_start, is_tcp):
    if index < ip_start:
        return GREEN
    elif index < tcp_start:
        return BLUE
    elif is_tcp and index < data_start:
        return YELLOW
    else:
        return RED


def print_raw_data(frame: FrameParser, fmt="bits"):
    ip_start = 14
    ihl = frame.ihl if frame.ihl else 5
    tcp_start = ip_start + (ihl * 4)

    data_offset = frame.data_offset if frame.data_offset else 5
    is_tcp = frame.protocol == 6
    data_start = tcp_start + (data_offset * 4) if is_tcp else tcp_start

    output = []
    for i, byte in enumerate(frame.raw_data):
        color = get_layer_color(i, ip_start, tcp_start, data_start, is_tcp)

        if fmt == "bits":
            text = f"{byte:08b}"
        else:
            text = f"{byte:02x}"

        output.append(f"{color}{text}")

    return " ".join(output)


def value_to_bits(val):
    if isinstance(val, bytes):
        return " ".join(f"{b:08b}" for b in val)
    elif isinstance(val, int):
        return bin(val)[2:]
    return "0"


def format_value(field_name, val):
    # MAC
    if field_name in ("d_mac", "s_mac") and isinstance(val, bytes) and len(val) == 6:
        return ":".join(f"{b:02x}" for b in val)

    # IP
    if field_name in ("s_ip", "d_ip") and isinstance(val, bytes) and len(val) == 4:
        return ".".join(str(b) for b in val)

    if isinstance(val, bytes):
        return int.from_bytes(val, "big")

    if isinstance(val, int):
        return val

    return str(val)


def print_frame_fields(frame: FrameParser, fmt="bits"):
    layers = [
        ("ETHERNET", ["d_mac", "s_mac", "ether_type"], GREEN),
        ("IP", [
            "version", "ihl", "qos", "total_length", "identification",
            "ip_flags", "fragment_offset", "ttl", "protocol",
            "header_checksum", "s_ip", "d_ip", "ip_options"
        ], BLUE),
        ("TCP", [
            "s_port", "d_port", "sequence_number", "acknowledgment_number",
            "data_offset", "tcp_flags", "window_size", "checksum",
            "urgent_pointer", "tcp_options"
        ], YELLOW),
        ("DATA", ["data"], RED),
    ]

    text = ""

    for layer_name, field_list, color in layers:
        label = "BITS" if fmt == "bits" else "INT / FORMATTED"
        for field in field_list:
            val = getattr(frame, field, None)
            if val is not None:
                if fmt == "bits":
                    formatted = value_to_bits(val)
                else:
                    formatted = format_value(field, val)

                text += f"{color}{field:22s}: {formatted}\n"

    return text


class MyApp(App):
    CSS = """
    HorizontalGroup {
        padding: 1;
    } 
    """
    def compose(self) -> ComposeResult:
        yield Header()
        yield Tabs("Raw Bits", "Raw Bytes", "Field Bits", "Field Numbers")
        yield HorizontalGroup(
            Select.from_values(os.listdir('/sys/class/net/')),
            Button.warning("Catch!")
        )
        yield RichLog(wrap=True, markup=True, auto_scroll=False)


    def on_button_pressed(self, event: Button.Pressed) -> None:
        sniffer = FrameSniffer(self.interface)
        raw_frame = sniffer.capture_frame()
        self.frame = FrameParser(raw_frame)

        self.text_box.clear()

        if self.label == "Raw Bits":
            self.text_box.write(print_raw_data(self.frame, fmt="bits"))
        elif self.label == "Raw Bytes":
            self.text_box.write(print_raw_data(self.frame, fmt="bytes"))
        elif self.label == "Field Bits":
            self.text_box.write(print_frame_fields(self.frame, fmt="bits"))
        elif self.label == "Field Numbers":
            self.text_box.write(print_frame_fields(self.frame, fmt="formatted"))



    @on(Tabs.TabActivated)
    def change_tabs(self, event: Tabs.TabActivated) -> None:
        active_tab = event.tab
        self.label = active_tab.label

        self.text_box.clear()

        if self.frame == None:
            self.text_box.write("Catch some frame.")

        else: 
            if self.label == "Raw Bits":
                self.text_box.write(print_raw_data(self.frame, fmt="bits"))
            elif self.label == "Raw Bytes":
                self.text_box.write(print_raw_data(self.frame, fmt="bytes"))
            elif self.label == "Field Bits":
                self.text_box.write(print_frame_fields(self.frame, fmt="bits"))
            elif self.label == "Field Numbers":
                self.text_box.write(print_frame_fields(self.frame, fmt="formatted"))


    @on(Select.Changed)
    def select_interface(self, event: Select.Changed) -> None:
        self.interface = str(event.value)


    def on_ready(self) -> None:
        self.frame = None

        self.text_box = self.query_one(RichLog)


        self.title = "FBBL"
        self.sub_title = "Small TUI app for inspecting frames."

if __name__ == "__main__":
    if os.geteuid() == 0:
        app = MyApp()
        app.run()

    else:
        print("Run as root pls")