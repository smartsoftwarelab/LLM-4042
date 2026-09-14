import random

from simulated_model import SimulatedModel
from validator import HanoiValidator
from export_results import ResultExporter
from report import Report

# ثابت کردن تولید اعداد تصادفی برای نتایج قابل بازتولید
random.seed(42)


class Experiment:

    def __init__(self, min_disks=2, max_disks=8):

        self.min_disks = min_disks
        self.max_disks = max_disks

    def run(self):

        results = []

        print("\n")
        print("=" * 90)
        print("CORRECT SOLUTIONS")
        print("=" * 90)

        print(
            f"{'Disks':<8}"
            f"{'Moves':<10}"
            f"{'Valid':<10}"
            f"{'Goal':<10}"
            f"{'Optimal':<10}"
        )

        correct_pass = 0

        for disks in range(self.min_disks, self.max_disks + 1):

            model = SimulatedModel(disks)

            moves = model.generate("correct")

            validator = HanoiValidator(disks)

            result = validator.validate(moves)

            if result["valid"]:
                correct_pass += 1

            results.append({

                "disks": disks,
                "mode": "Correct",

                "valid": result["valid"],
                "goal": result["goal_reached"],
                "optimal": result["optimal"],

                "legal_moves": result["legal_moves"],
                "illegal_moves": result["illegal_moves"],

                "failed_step": result["failed_step"],
                "total_moves": result["total_moves"],

                "message": result["message"]
            })

            print(
                f"{disks:<8}"
                f"{result['total_moves']:<10}"
                f"{str(result['valid']):<10}"
                f"{str(result['goal_reached']):<10}"
                f"{str(result['optimal']):<10}"
            )

        print("\n")
        print("=" * 90)
        print("INCORRECT SOLUTIONS")
        print("=" * 90)

        print(
            f"{'Disks':<8}"
            f"{'Moves':<10}"
            f"{'Valid':<10}"
            f"{'Failed Step':<15}"
            f"{'Reason'}"
        )

        incorrect_detected = 0

        for disks in range(self.min_disks, self.max_disks + 1):

            model = SimulatedModel(disks)

            moves = model.generate("random")

            validator = HanoiValidator(disks)

            result = validator.validate(moves)

            if not result["valid"]:
                incorrect_detected += 1

            results.append({

                "disks": disks,
                "mode": "Incorrect",

                "valid": result["valid"],
                "goal": result["goal_reached"],
                "optimal": result["optimal"],

                "legal_moves": result["legal_moves"],
                "illegal_moves": result["illegal_moves"],

                "failed_step": result["failed_step"],
                "total_moves": result["total_moves"],

                "message": result["message"]
            })

            print(
                f"{disks:<8}"
                f"{result['total_moves']:<10}"
                f"{str(result['valid']):<10}"
                f"{str(result['failed_step']):<15}"
                f"{result['message']}"
            )

        print("\n")
        print("=" * 90)
        print("SUMMARY")
        print("=" * 90)

        total = self.max_disks - self.min_disks + 1

        print(f"Correct Solutions Passed : {correct_pass}/{total}")
        print(f"Incorrect Solutions Detected : {incorrect_detected}/{total}")

        accuracy = (
            (correct_pass + incorrect_detected)
            / (2 * total)
        ) * 100

        print(f"Overall Accuracy : {accuracy:.2f}%")

        ResultExporter.save(results)

        Report.generate(results)