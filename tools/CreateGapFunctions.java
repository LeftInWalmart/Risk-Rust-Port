// Create functions for code Ghidra's auto-analysis skipped: any non-zero, non-function bytes
// between functions in executable blocks (typically small virtual methods and callbacks that
// are only reached through pointers). Repeats until nothing new is found.
// Only the given code range is scanned (a PS-X EXE is one block that also holds .rdata/.data).
// Usage: ghidra script run CreateGapFunctions.java -- <start hex> <end hex>
//@category Analysis
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class CreateGapFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        int created = 0, pass = 0;
        boolean changed = true;
        while (changed && pass < 8) {
            changed = false;
            pass++;
            for (MemoryBlock b : mem.getBlocks()) {
                if (!b.isExecute() || !b.isInitialized()) continue;
                AddressSpace sp = b.getStart().getAddressSpace();
                Address a = sp.getAddress(Long.parseLong(getScriptArgs()[0].replace("0x", ""), 16));
                Address end = sp.getAddress(Long.parseLong(getScriptArgs()[1].replace("0x", ""), 16));
                if (!b.contains(a)) continue;
                while (a.compareTo(end) < 0 && !monitor.isCancelled()) {
                    Function f = fm.getFunctionContaining(a);
                    if (f != null) {
                        Address next = f.getBody().getMaxAddress().add(1);
                        a = next.compareTo(a) > 0 ? next : a.add(4);
                        continue;
                    }
                    if (mem.getInt(a) == 0) {
                        a = a.add(4);
                        continue;
                    }
                    if (listing.getInstructionAt(a) == null) {
                        DisassembleCommand dis = new DisassembleCommand(a, null, true);
                        dis.applyTo(currentProgram, monitor);
                    }
                    if (listing.getInstructionAt(a) != null
                            && new CreateFunctionCmd(a).applyTo(currentProgram, monitor)) {
                        created++;
                        changed = true;
                        Function nf = fm.getFunctionAt(a);
                        a = nf != null ? nf.getBody().getMaxAddress().add(1) : a.add(4);
                    } else {
                        a = a.add(4);
                    }
                }
            }
            println("pass " + pass + ": " + created + " functions created so far");
        }
        println("done: created " + created + " functions, total " + fm.getFunctionCount());
    }
}
