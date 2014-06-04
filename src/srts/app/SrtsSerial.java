package srts.app;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import srts.Pvs;
import srts.Utils;

public class SrtsSerial {

	private static String filePrefix = "cpabe_";
	private static String filePostfix = ".txt";

	public static void main(String[] args) throws Exception {

		String currentPath = System.getProperty("user.dir") + File.separator;
		String mPath = currentPath + "m" + File.separator;
		String keysPath = currentPath + "keys" + File.separator;
		String mcsPath = currentPath + "mcs" + File.separator;

		String pkFile = keysPath + "pk";
		String skFile = keysPath + "sk";
		String gFile = keysPath + "g";
		String yFile = keysPath + "y";

		String resultFile = currentPath + "srts_serial.csv";

		Utils.checkPath(keysPath);
		Utils.checkPath(mcsPath);

		int numofSamples = 0;
		int commitAlgorithm = 0;

		if (args.length > 0) {
			if (args[0].equals("-h")) {
				System.out.println("Usage:");
				System.out.println("srts_serial [numofSamples] [commitAlgorithm]");
				System.exit(0);
			}

			if (args.length > 0) {
				numofSamples = Integer.parseInt(args[0]);
				commitAlgorithm = Integer.parseInt(args[1]);
			}
		}

		Pvs pvs = new Pvs();
		pvs.keygen(pkFile, skFile, gFile, yFile);

		writeLine(resultFile, "inputFile,commitAlgo,priSign,priVerify,check\n");

		long tStart = 0;
		long tEnd = 0;
		long tPriSign = 0;
		long tPriVerify = 0;
		long tCheck = 0;

		for (int i = 0; i < numofSamples; i++) {
			String mFile = mPath + filePrefix + i + filePostfix;
			String mcsFile = mcsPath + filePrefix + i + filePostfix + ".mcs";

			tStart = System.currentTimeMillis();
			pvs.priSign(pkFile, skFile, yFile, mFile, mcsFile, commitAlgorithm);
			tEnd = System.currentTimeMillis();
			tPriSign = tEnd - tStart;

			tStart = System.currentTimeMillis();
			if (pvs.priVerify(pkFile, gFile, mcsFile)) {
				System.out.println("[" + i + "]priVerify TRUE!!");
			} else {
				System.out.println("[" + i + "]priVerify FALSE!!");
			}
			tEnd = System.currentTimeMillis();
			tPriVerify = tEnd - tStart;

			tStart = System.currentTimeMillis();
			if (pvs.check(pkFile, yFile, mFile, mcsFile, commitAlgorithm)) {
				System.out.println("[" + i + "]check TRUE!!");
			} else {
				System.out.println("[" + i + "]check FALSE!!");
			}
			tEnd = System.currentTimeMillis();
			tCheck = tEnd - tStart;

			if(commitAlgorithm == Pvs.COMMIT_HA_BASED)
			{
				writeLine(resultFile, mFile + ",HA_based," + tPriSign + "," + tPriVerify
						+ "," + tCheck + "\n");
			}
			else if(commitAlgorithm == Pvs.COMMIT_PE_BASED)
			{
				writeLine(resultFile, mFile + ",PE_based," + tPriSign + "," + tPriVerify
						+ "," + tCheck + "\n");
			}
			
		}
	}

	private static void writeLine(String file, String line) {
		try {
			File f = new File(file);
			if (!f.exists()) {
				f.createNewFile();
			}
			BufferedWriter output = new BufferedWriter(new FileWriter(f, true));
			output.append(line);
			output.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
