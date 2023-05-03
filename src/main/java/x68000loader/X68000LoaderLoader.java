/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package x68000loader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class X68000Header {
	int data_offset; // 0 = relocatable
	int entrypoint;
	int text_len;
	int data_len;
	int ram_len;
	int reloc_len;
	int line_num_table_len;
}

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class X68000LoaderLoader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {
		return "X68000 .X File Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		byte[] magic = provider.readBytes(0, 4);
		
		if (magic[0] != 0x48 && magic[1] != 0x55) {
			throw new IOException("File is not a X68000 .X file");
		}

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:MC68020", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		BinaryReader reader = new BinaryReader(provider, false);
		X68000Header header = new X68000Header();
		reader.readNextInt(); // discard magic
		header.data_offset = reader.readNextInt();
		header.entrypoint = reader.readNextInt();
		header.text_len = reader.readNextInt();
		header.data_len = reader.readNextInt();
		header.ram_len = reader.readNextInt();
		header.reloc_len = reader.readNextInt();
		header.line_num_table_len = reader.readNextInt();
		reader.readNextByteArray(32); // throw away padding
		
		InputStream inStreamText = provider.getInputStream(0x40);

		Memory mem = program.getMemory();
		try {
			mem.createInitializedBlock("text", api.toAddr(header.data_offset), inStreamText, header.text_len, monitor, false);
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException
				| IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		api.createFunction(api.toAddr(header.entrypoint), "_start");
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
