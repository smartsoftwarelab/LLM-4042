from experiment import Experiment

from plot_results import generate_plot
from failure_plot import generate_plot as generate_failure_plot
from complexity_plot import generate_plot as generate_complexity_plot


def main():

    experiment = Experiment(5)

    experiment.run()

    print("\nGenerating plots...\n")

    generate_plot()
    generate_failure_plot()
    generate_complexity_plot()

    print("All plots generated successfully.")


if __name__ == "__main__":
    main()