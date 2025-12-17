import subprocess
import json
import tempfile
import os
from typing import Dict, Any, Optional
import frida
import socket

class ReverseEngineeringTools:
    """Integration with Ghidra, Frida, and Flutter analysis tools"""
    
    @staticmethod
    def analyze_with_ghidra(file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze binary using Ghidra (requires Ghidra installation)"""
        try:
            # Create analysis script
            analysis_script = """
import sys
from ghidra_bridge import GhidraBridge
            
def analyze_binary():
    bridge = GhidraBridge()
    flat_api = bridge.get_flat_api()
    
    # Import and analyze
    program = flat_api.importFile(file_path)
    flat_api.analyzeAll(program)
    
    # Extract information
    info = {
        "entry_points": [],
        "functions": [],
        "imports": [],
        "exports": []
    }
    
    # Get entry points
    for entry_point in flat_api.getEntryPoints(program):
        info["entry_points"].append(str(entry_point))
    
    # Get functions
    func_manager = program.getFunctionManager()
    functions = func_manager.getFunctions(True)
    for func in functions:
        info["functions"].append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        })
    
    return info

if __name__ == "__main__":
    result = analyze_binary()
    print(json.dumps(result))
"""
            
            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(analysis_script)
                script_path = f.name
            
            # Execute analysis (requires ghidra_bridge server running)
            result = subprocess.run(
                ["python", script_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            os.unlink(script_path)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
                
        except Exception as e:
            print(f"Ghidra analysis error: {e}")
            
        return None
    
    @staticmethod
    def attach_with_frida(process_name: str) -> Dict[str, Any]:
        """Attach to process using Frida for dynamic analysis"""
        results = {
            "modules": [],
            "exports": [],
            "hooks": []
        }
        
        try:
            # Connect to device
            device = frida.get_usb_device()
            
            # Attach to process
            session = device.attach(process_name)
            
            # Basic script to enumerate modules
            script_code = """
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        console.log("open() called with path: " + Memory.readUtf8String(args[0]));
        this.path = Memory.readUtf8String(args[0]);
    },
    onLeave: function(retval) {
        console.log("open() returned: " + retval);
    }
});

// Enumerate modules
Process.enumerateModules({
    onMatch: function(module){
        console.log('Module: ' + module.name + ' Base: ' + module.base + ' Size: ' + module.size);
    },
    onComplete: function(){
        console.log('Module enumeration complete');
    }
});
"""
            
            script = session.create_script(script_code)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    print(f"[*] {message['payload']}")
                    results["hooks"].append(message['payload'])
            
            script.on('message', on_message)
            script.load()
            
            # Keep script running briefly
            import time
            time.sleep(2)
            
            session.detach()
            
        except Exception as e:
            results["error"] = str(e)
            
        return results
    
    @staticmethod
    def analyze_flutter_app(apk_path: str) -> Optional[Dict[str, Any]]:
        """Analyze Flutter applications"""
        try:
            # Use jadx or similar tools for decompilation
            # This is a simplified version
            results = {
                "flutter_detected": False,
                "flutter_version": None,
                "assets": [],
                "libflutter.so": False
            }
            
            # Check for Flutter library
            if os.path.exists(apk_path):
                # Extract and analyze (simplified)
                import zipfile
                with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    
                    # Check for Flutter indicators
                    if any("libflutter.so" in f for f in file_list):
                        results["flutter_detected"] = True
                        results["libflutter.so"] = True
                    
                    # List assets
                    results["assets"] = [f for f in file_list if f.startswith("assets/")]
            
            return results
            
        except Exception as e:
            print(f"Flutter analysis error: {e}")
            
        return None