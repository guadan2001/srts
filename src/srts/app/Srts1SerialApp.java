package srts.app;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import srts.Srts1Serial;
import srts.Utils;

public class Srts1SerialApp {

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

		String resultFile = currentPath + "srts1_serial_result.csv";

		Utils.checkPath(keysPath);
		Utils.checkPath(mcsPath);

		int numofSamples = 0;
		int commitAlgorithm = 0;

		if (args.length > 0) {
			if (args[0].equals("-h")) {
				System.out.println("Usage:");
				System.out.println("srts1_serial [numofSamples] [commitAlgorithm]");
				System.exit(0);
			}

			if (args.length > 0) {
				numofSamples = Integer.parseInt(args[0]);
				commitAlgorithm = Integer.parseInt(args[1]);
			}
		}

		Srts1Serial srts1 = new Srts1Serial();
		srts1.keygen(pkFile, skFile, gFile, yFile);

		writeLine(resultFile, "samples,commitAlgo,priSign,priVerify,check\n");

		long tStart = 0;
		long tEnd = 0;
		long tPriSign = 0;
		long tPriVerify = 0;
		long tCheck = 0;
		
		String[] mFiles = new String[numofSamples];
		String[] mcsFiles = new String[numofSamples];

		for (int i = 0; i < numofSamples; i++) {
			String mFile = mPath + filePrefix + i + filePostfix;
			String mcsFile = mcsPath + filePrefix + i + filePostfix + ".mcs";
			
			mFiles[i] = mFile;
			mcsFiles[i] = mcsFile;
		}
		
		tStart = System.currentTimeMillis();
		srts1.priSign(pkFile, skFile, yFile, mFiles, mcsFiles, commitAlgorithm);
		tEnd = System.currentTimeMillis();
		tPriSign = tEnd - tStart;

		tStart = System.currentTimeMillis();
		if (srts1.priVerify(pkFile, gFile, mcsFiles)) {
			System.out.println("priVerify TRUE!!");
		} else {
			System.out.println("priVerify FALSE!!");
		}
		tEnd = System.currentTimeMillis();
		tPriVerify = tEnd - tStart;

		tStart = System.currentTimeMillis();
		if (srts1.check(pkFile, yFile, mFiles, mcsFiles, commitAlgorithm)) {
			System.out.println("check TRUE!!");
		} else {
			System.out.println("check FALSE!!");
		}
		tEnd = System.currentTimeMillis();
		tCheck = tEnd - tStart;

		if(commitAlgorithm == Srts1Serial.COMMIT_HA_BASED)
		{
			writeLine(resultFile, numofSamples + ",HA_based," + tPriSign + "," + tPriVerify
					+ "," + tCheck + "\n");
		}
		else if(commitAlgorithm == Srts1Serial.COMMIT_PE_BASED)
		{
			writeLine(resultFile, numofSamples + ",PE_based," + tPriSign + "," + tPriVerify
					+ "," + tCheck + "\n");
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
