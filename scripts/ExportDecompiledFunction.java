// Ghidra Headless script to decompile a specific function to C pseudo-code
// @category OmniReverse

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import java.io.File;
import java.io.FileWriter;

public class ExportDecompiledFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String query = args.length > 0 ? args[0] : "";
        String outPath = args.length > 1 ? args[1] : "decompiled_out.c";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Function targetFunc = null;
        if (query.startsWith("0x") || query.startsWith("0X")) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(query);
                targetFunc = getFunctionAt(addr);
                if (targetFunc == null) {
                    targetFunc = getFunctionContaining(addr);
                }
            } catch (Exception e) {
                println("Address parse error: " + e.getMessage());
            }
        } else if (!query.isEmpty()) {
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                Function f = iter.next();
                if (f.getName().equalsIgnoreCase(query)) {
                    targetFunc = f;
                    break;
                }
            }
        }

        if (targetFunc == null) {
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            if (iter.hasNext()) {
                targetFunc = iter.next();
            }
        }

        if (targetFunc != null) {
            DecompileResults results = decomp.decompileFunction(targetFunc, 30, monitor);
            if (results.decompileCompleted()) {
                String cCode = "// Decompiled by OmniReverse (Ghidra Engine)\n// Function: " + targetFunc.getName() + " @ " + targetFunc.getEntryPoint() + "\n\n" + results.getDecompiledFunction().getC();
                FileWriter writer = new FileWriter(new File(outPath));
                writer.write(cCode);
                writer.close();
                println("SUCCESS: Decompiled function written to " + outPath);
            } else {
                println("ERROR: Decompile failed -> " + results.getErrorMessage());
            }
        } else {
            println("ERROR: Target function not found: " + query);
        }
    }
}
